# OCIブートボリュームのバックアップと復旧

この構成では、OCI中継サーバーのブートボリュームをTerraform管理のポリシーで週次バックアップします。VMが回収・破損した場合は、選択したバックアップから新しいブートボリュームとVMを作り直せます。

バックアップには、VM上のWireGuard設定、秘密鍵、SSHホスト鍵、nftables設定、管理スクリプトなども含まれます。バックアップとTerraform stateを読み取れるIAMユーザーを必要最小限に制限してください。

## 通常時のバックアップ

既定値は次のとおりです。

- 毎週月曜日の03:00を開始時刻として指定
- リージョンのデータセンター時刻を使用
- 増分バックアップ
- 14日間保持
- VMを停止せずに取得するクラッシュ整合性バックアップ

OCIの混雑状況によって、実際の開始が指定時刻から数時間遅れる場合があります。また、ポリシーを割り当てた直後にはバックアップは作成されず、次のスケジュールから開始されます。

設定は`terraform.tfvars`で変更できます。

```hcl
enable_boot_volume_backups        = true
boot_volume_backup_retention_days = 14
boot_volume_backup_day_of_week    = "MONDAY"
boot_volume_backup_hour           = 3
```

週次・14日保持なら、通常は同時に残るバックアップが2〜3件程度となります。保持期間は7〜28日の範囲に制限しています。Always Freeではテナンシー全体で利用できるボリュームバックアップ数に上限があるため、ほかのボリュームを含めてOCIコンソールで定期的に確認してください。

初めて有効化するときは、次のように確認して適用します。

```sh
terraform plan -out=tfplan
terraform apply tfplan
```

既存環境へ追加する通常のplanでは、次の2リソースだけが作成され、VMの置換が表示されないことを確認してください。

- `oci_core_volume_backup_policy.relay[0]`
- `oci_core_volume_backup_policy_assignment.relay[0]`

## バックアップを確認する

OCIコンソールでは、ナビゲーションメニューから「ストレージ」→「ブロック・ストレージ」→「ブート・ボリューム・バックアップ」を開きます。コンパートメントを選択し、対象バックアップの状態が`AVAILABLE`になっていることを確認します。

OCI CLIでは、現在のブートボリュームを指定して一覧を確認できます。

```sh
oci bv boot-volume-backup list \
  --compartment-id "実際のコンパートメントOCID" \
  --boot-volume-id "$(terraform output -raw boot_volume_id)" \
  --all
```

復旧に使うバックアップのOCID、状態、作成日時を記録してください。

次の定期実行を待たず、現在の復旧ポイントをすぐに1件作る必要がある場合は、手動バックアップを作成できます。

```sh
oci bv boot-volume-backup create \
  --boot-volume-id "$(terraform output -raw boot_volume_id)" \
  --display-name "onprem-relay-initial-manual-backup" \
  --type INCREMENTAL \
  --wait-for-state AVAILABLE
```

手動バックアップはこのTerraform構成の管理対象外で、自動的には期限切れになりません。週次バックアップが`AVAILABLE`になった後、不要ならOCIコンソールまたはCLIから手動バックアップを削除してください。Always Freeの5件上限にも含まれます。

## バックアップから復旧する

この操作は、Terraformが現在管理しているVMを新しいVMへ置換します。元のVMがまだ動作している場合も破棄対象になるため、障害復旧が必要であることと、使用するバックアップを十分に確認してください。

1. OCIコンソールまたはCLIで、状態が`AVAILABLE`のバックアップを選びます。
2. `instance_shape`はバックアップ取得時と同じCPUアーキテクチャのままにします。E2 Micro（x86）とA1 Flex（Arm）を同時に切り替えないでください。
3. `terraform.tfvars`へ次の設定を追加します。

```hcl
restore_boot_volume_backup = {
  id                           = "ocid1.bootvolumebackup.oc1.ap-tokyo-1...実際のOCID"
  confirm_instance_replacement = true
}
```

4. 保存済みplanを流用せず、新しいplanを作成します。

```sh
terraform plan -out=tfplan
```

5. planで次の内容を確認します。

- `oci_core_boot_volume.relay_restore[0]`がバックアップから作成される
- `oci_core_instance.relay_image[0]`が削除され、`oci_core_instance.relay_restore[0]`が作成される
- 予約済みパブリックIPv4アドレスは削除されず、新しいVMへ付け替えられる
- バックアップポリシーの割り当てが新しいブートボリュームへ付け替えられる
- 意図しないネットワークや予算リソースが変更されない

6. 内容に問題がなければ適用します。

```sh
terraform apply tfplan
```

7. 出力と疎通を確認します。

```sh
terraform output public_ipv4
terraform output restore_mode_active
terraform output restored_boot_volume_id
ssh oci-relay
ping 10.99.0.1
```

復旧後も`restore_boot_volume_backup`の設定は残してください。この値を削除すると、Terraformは通常のUbuntuイメージからVMを作るモードへ戻り、復旧済みVMを再度置換します。

予約済みパブリックIPv4アドレスは維持されますが、IPv6アドレスは新しいVNICで変わります。DNSにAAAAレコードを設定している場合は、`terraform output public_ipv6_addresses`の値へ更新してください。

## バックアップから戻せないもの

ブートボリュームのバックアップだけでは、次のTerraform管理リソースは復元されません。これらはTerraform stateと構成ファイルから再作成します。

- VCN、サブネット、NSG、ルート表
- 予約済みパブリックIPv4アドレス
- 予算とアラート
- バックアップポリシー

したがって、Gitリポジトリ、OCI Object Storage上のTerraform state、OCI APIキーの復旧手段も別に維持してください。

## 削除時の注意

`terraform destroy`は、VM、復旧用ブートボリューム、バックアップポリシーと割り当ても削除対象にします。既に作成済みのバックアップはOCI側の保持期限まで残る場合があるため、削除前後にOCIコンソールで対象と課金状況を確認してください。

この構成では、保存容量が別途課金対象になるカスタムイメージは使用しません。OSを含む中継サーバーの復旧には、Always Freeの対象範囲を利用しやすいブートボリュームバックアップを使用します。
