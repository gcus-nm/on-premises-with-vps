# オンプレミスサーバー向けOCI中継サーバー

このTerraform構成は、Oracle Cloud Infrastructure（OCI）上に小さな中継サーバーを作成します。

想定している通信経路は次のとおりです。

```text
インターネット上のクライアント
  ↓ IPv4 / IPv6
OCI中継サーバー
  ↓ WireGuardトンネル
オンプレミスサーバー
```

OCIはインターネットからの通信受付とパケット転送だけを担当します。アプリケーションの処理、データ、ディスクはオンプレミスサーバーに残すことで、VPS側のリソースと費用を最小限に抑えます。

## 作成されるリソース

- IPv4/IPv6デュアルスタックのVCN
- IPv4/IPv6対応のパブリックサブネット
- Internet Gatewayとデフォルトルート
- VM単位で通信を制御するNetwork Security Group（NSG）
- `VM.Standard.E2.1.Micro`のx86 VM 1台
  - 既定値: メモリ1 GiB、インターネット帯域最大50 Mbps
  - A1に空きがある場合は`VM.Standard.A1.Flex`へ切替可能
  - ブートボリューム: 50 GiB
- VMを作り直しても再割り当てできる予約済みパブリックIPv4アドレス
- パブリックIPv6アドレス
- WireGuard用UDP/51820の受信許可
- 任意で追加できる公開TCP/UDPポート
- WireGuard、nftablesのインストール
- IPv4/IPv6パケット転送の有効化
- 月次予算と実費発生時のメールアラート（通知先を設定した場合）
- 週次の増分ブートボリュームバックアップ（既定で14日保持）
- 選択したブートボリュームバックアップからVMを作り直す明示的な障害復旧モード

Terraform適用直後の段階では、WireGuardの秘密鍵、Peer設定、DNSレコード、実際のポート転送ルールは作成しません。WireGuardの初期化とPeer管理には、設定ファイルを直接編集せずに操作できる管理スクリプトを使用します。詳しい手順は[WireGuard中継の管理](WIREGUARD.md)を参照してください。

Windows Docker DesktopでTraefikをHTTPS入口として使用し、ゲームはOCIから各公開ポートへ
直接転送する手順は[Docker入口とゲームポート転送](GATEWAY.md)を参照してください。
Relay ControlからHTTPSの`ドメイン → Dockerサービス:ポート`と、ゲームごとのTCP/UDP転送を
管理できます。

OCI公開ポートとWireGuard転送経路をブラウザから管理する場合は[OCI Relay Control](relay-dashboard/README.md)を使用できます。MiniPCのDocker Desktop上で動作し、安全性を検査したTerraform planを確認してから適用します。

VM内部を週次バックアップし、障害時に復旧する手順は[OCIブートボリュームのバックアップと復旧](BACKUP.md)を参照してください。

MyDNS.JPのChild IDを使ってOCIの予約済みIPv4をサブドメインへ定期通知する場合は、
[MyDNS.JPへのIPv4通知](MYDNS.md)を参照してください。認証情報はTerraformやGitへ
保存せず、OCI VM内のroot専用ファイルで管理します。

## 無料枠についての注意

OCIの[Always Free公式ドキュメント](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)では、`VM.Standard.E2.1.Micro`は最大2台、Ampere A1はテナンシー全体で合計2 OCPU・メモリ12 GiB相当が無料枠です。ブロックボリュームはテナンシー全体で合計200 GBまでです。

この構成は、既定でE2 Micro 1台、ブートボリューム50 GiB、週次バックアップを使用します。Always Freeにはテナンシー全体で5件のボリュームバックアップが含まれますが、同じテナンシーで既に無料枠を使っている場合、上限を超えたり有料になったりする可能性があります。適用前に必ずTerraformのplanとOCIコンソールの利用状況を確認してください。

Always FreeのComputeインスタンスは、Oracleが定める低稼働状態が続くと回収される可能性があります。通信量の少ない中継サーバーは条件に該当する可能性があるため、高可用性が必要な本番用途ではこの点を許容できるか検討してください。

Always FreeのComputeは、テナンシーの**ホームリージョン**に作成する必要があります。`Out of host capacity`が発生した場合は時間をおいて再実行するか、`instance_shape`でE2 MicroとA1を切り替えてください。

関連するOCI公式資料:

- [OCI Free Tier](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier.htm)
- [Always Freeリソース](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
- [OCIのIPv6アドレス](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/ipv6.htm)
- [OCIのパブリックIPアドレス](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingpublicIPs.htm)

## 1. 必要なものを準備する

以下が必要です。

- OCIアカウント
- Terraform 1.6以降
- OCI APIキー
- SSH公開鍵
- 作成先コンパートメントのOCID
- OCIテナンシーのホームリージョン名

ホームリージョンはOCIコンソールのテナンシー詳細で確認できます。東京リージョンの場合は`ap-tokyo-1`ですが、無料枠を利用する場合は自分のテナンシーに設定されているホームリージョンを指定してください。

## 2. Terraformをインストールする

macOSでHomebrewを利用する場合の例です。

```sh
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
terraform version
```

Terraform 1.6以降であることを確認してください。

## 3. OCI APIキーを設定する

OCI CLIを利用できる場合は、次のコマンドで`~/.oci/config`を作成できます。

```sh
oci setup config
```

設定後のファイルは、おおむね次の形式になります。

```ini
[DEFAULT]
user=ocid1.user.oc1..xxxxx
fingerprint=xx:xx:xx:xx:xx
tenancy=ocid1.tenancy.oc1..xxxxx
region=ap-tokyo-1
key_file=/Users/your-name/.oci/oci_api_key.pem
```

API秘密鍵はこのリポジトリに置かないでください。Terraformは既定で`~/.oci/config`の`DEFAULT`プロファイルを使用します。別のプロファイルを使う場合は、`oci_config_profile`変数で指定できます。

## 4. SSH鍵を作成する

既存のSSH鍵を利用しても構いません。新しく作成する場合は次のように実行します。

```sh
ssh-keygen -t ed25519 -f ~/.ssh/oci-relay
```

Terraformに指定するのは公開鍵である`~/.ssh/oci-relay.pub`の内容です。秘密鍵を`terraform.tfvars`へ記載しないでください。

## 5. Terraform変数を設定する

リポジトリのルートで、サンプルをコピーします。

```sh
cp terraform.tfvars.example terraform.tfvars
```

`terraform.tfvars`を編集します。

```hcl
region           = "ap-tokyo-1"
compartment_ocid = "ocid1.compartment.oc1..実際のOCID"
ssh_public_key   = "ssh-ed25519 AAAA...実際の公開鍵"

# SSHを許可する管理端末のグローバルIPアドレスです。
# 例のアドレスをそのまま使用しないでください。
ssh_ingress_cidrs = ["203.0.113.10/32"]

# OCIで受付け、後からオンプレミスへ転送するポートです。
public_tcp_ports = [80, 443]
public_udp_ports = []

# 公開サービスへ接続できる送信元です。
# 完全公開しない場合は、接続元CIDRへ絞ってください。
public_ingress_cidrs = ["0.0.0.0/0", "::/0"]

# OCIの請求通貨単位です。通知先を空にすると予算リソースを作成しません。
budget_amount           = 100
budget_alert_threshold  = 1
budget_alert_recipients = ["admin@example.com"]
```

現在利用中のグローバルIPv4アドレスは、例えば次のように確認できます。

```sh
curl -4 https://ifconfig.me
```

確認したアドレスが`198.51.100.25`なら、SSH用の指定は`198.51.100.25/32`です。管理端末からIPv6でSSH接続する場合は、そのIPv6アドレスを`/128`で追加します。

`terraform.tfvars`はGitの対象外になっていますが、次の情報は記載しないでください。

- OCI API秘密鍵
- SSH秘密鍵
- WireGuard秘密鍵
- パスワード
- APIトークン

通知先メールアドレスはTerraform stateにも保存されます。この構成ではstateを非公開のOCI Object Storageへ保存しますが、stateを読めるIAMユーザーは通知先も参照できる点に注意してください。

### 予算アラートについて

`budget_alert_recipients`に1件以上のメールアドレスを指定すると、Terraformは月次予算と実費ベースのアラートルールを作成します。`budget_amount`と`budget_alert_threshold`は、OCIテナンシーのレートカードに設定された請求通貨の単位です。例えば請求通貨が日本円なら`100`は100円ですが、米ドルなら100ドルです。適用前にOCIコンソールのBilling & Cost Managementで請求通貨を確認してください。

アラートは課金を停止するハードリミットではありません。OCI側で定期評価されるため、利用開始から通知まで時間差が生じることがあります。

子コンパートメントを監視する場合は`tenancy_ocid`にルートテナンシーOCID、`compartment_ocid`に監視対象コンパートメントOCIDを指定します。ルートテナンシー自体を監視する現在の構成では、`compartment_ocid`がテナンシーOCIDなので`tenancy_ocid`は省略できます。

## 6. Terraformを初期化する

```sh
terraform init
```

この処理でOracle OCI Providerが取得されます。

## 7. 書式と構成を検証する

```sh
terraform fmt -check
terraform validate
```

`Success! The configuration is valid.`と表示されることを確認します。

## 8. 作成内容を確認する

```sh
terraform plan -out=tfplan
```

planでは、特に次の項目を確認してください。

- リージョンがホームリージョンになっていること
- Compute Shapeが`VM.Standard.E2.1.Micro`であること
- E2 Microの固定スペックがメモリ1 GiBであること
- ブートボリュームが50 GiBであること
- 意図しない有料リソースが含まれていないこと
- 予算額・実費アラートしきい値・通知先が正しいこと
- ブートボリュームのバックアップ保持期間と実行曜日・時刻が正しいこと
- `restore_boot_volume_backup`を設定していない通常時にVMの置換が含まれないこと
- SSHが意図した送信元CIDRだけに許可されていること
- 公開TCP/UDPポートが必要最小限であること

## 9. OCIリソースを作成する

planの内容に問題がなければ適用します。

```sh
terraform apply tfplan
```

Computeの空きがない場合は`Out of host capacity`になることがあります。時間をおいて再試行するか、`terraform.tfvars`のShapeを切り替えて再度planします。

```hcl
instance_shape = "VM.Standard.A1.Flex"
```

A1を選択した場合は既定で1 OCPU・メモリ6 GiBです。東京リージョンにはAvailability Domainが1つしかないため、`availability_domain_index`の変更では在庫不足を回避できません。

## 10. 作成されたIPアドレスを確認する

```sh
terraform output public_ipv4
terraform output public_ipv6_addresses
terraform output wireguard_endpoint_ipv4
terraform output ssh_command
```

WireGuardのIPv4エンドポイントは次の形式で出力されます。

```text
203.0.113.20:51820
```

## 11. SSH接続を確認する

`ssh_ingress_cidrs`へ現在の接続元を設定している場合は、次のように接続できます。

```sh
ssh -i ~/.ssh/oci-relay ubuntu@$(terraform output -raw public_ipv4)
```

接続後、cloud-initの完了状態を確認します。

```sh
cloud-init status --wait
wg --version
sudo nft --version
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding
```

IP forwardingの値がどちらも`1`になっていれば、パケット転送の事前準備は完了しています。

SSHできない場合は次を確認してください。

- `ssh_ingress_cidrs`が現在の送信元IPと一致しているか
- SSH秘密鍵が、Terraformへ指定した公開鍵と対になっているか
- OCIコンソールでインスタンスが`RUNNING`になっているか
- cloud-initが完了しているか

## 主な変数

| 変数 | 既定値 | 用途 |
| --- | --- | --- |
| `region` | 必須 | OCIのホームリージョン |
| `compartment_ocid` | 必須 | 作成先コンパートメントまたはルートテナンシーのOCID |
| `tenancy_ocid` | `null` | 子コンパートメントへ予算を設定する場合のルートテナンシーOCID |
| `ssh_public_key` | 必須 | `ubuntu`ユーザーへ設定するSSH公開鍵 |
| `oci_config_profile` | `DEFAULT` | 使用する`~/.oci/config`プロファイル |
| `availability_domain_index` | `0` | VMを作成するAvailability Domainの番号 |
| `instance_shape` | `VM.Standard.E2.1.Micro` | E2 MicroまたはA1 Flexを選択 |
| `instance_ocpus` | `1` | A1選択時のOCPU数。E2 Microでは未使用 |
| `instance_memory_gbs` | `6` | A1選択時のメモリ容量。E2 Microでは未使用 |
| `wireguard_port` | `51820` | WireGuardの待受UDPポート |
| `public_tcp_ports` | `[]` | 後からオンプレミスへ転送するTCPポート |
| `public_udp_ports` | `[]` | 後からオンプレミスへ転送するUDPポート |
| `dashboard_public_tcp_ports` | `[]` | 管理画面がplan時に渡すTCPポート。通常は直接設定しない |
| `dashboard_public_udp_ports` | `[]` | 管理画面がplan時に渡すUDPポート。通常は直接設定しない |
| `public_ingress_cidrs` | IPv4/IPv6全体 | WireGuard・公開サービスへ接続できる送信元 |
| `ssh_ingress_cidrs` | `[]` | SSHを許可する管理元。空ならSSHは閉鎖 |
| `image_ocid` | `null` | Ubuntuイメージの自動選択を上書きする場合に指定 |
| `enable_boot_volume_backups` | `true` | 週次ブートボリュームバックアップの有効化 |
| `boot_volume_backup_retention_days` | `14` | 週次バックアップの保持日数（7〜28日） |
| `boot_volume_backup_day_of_week` | `MONDAY` | バックアップを開始する曜日 |
| `boot_volume_backup_hour` | `3` | リージョンのデータセンター時刻での開始時刻 |
| `restore_boot_volume_backup` | `null` | 障害復旧時に使用するバックアップOCIDとVM置換確認 |
| `budget_amount` | `100` | 月次予算。OCIの請求通貨単位 |
| `budget_alert_threshold` | `1` | 実費アラートを送る金額。OCIの請求通貨単位 |
| `budget_alert_recipients` | `[]` | 通知先メールアドレス。空なら予算管理を無効化 |

## 次の段階: WireGuardトンネルの構築

設定ファイルを直接編集せずに、OCIの初期化とPeerの追加・更新・削除を行えます。

```sh
./scripts/wg-relay.sh install
./scripts/wg-relay.sh init
./scripts/wg-relay.sh add windows-minibox --address 10.99.0.2/32
```

Windowsへインポートする設定は`generated/wireguard/windows-minibox.conf`へ作成されます。このファイルにはWindows側秘密鍵が含まれ、Git管理対象外です。詳細は[WIREGUARD.md](WIREGUARD.md)を確認してください。

MacからWindowsへのRDPなど、WireGuard Peer間で必要な通信だけを許可する場合は`peer-forward`を使用します。RDPの例とクライアント側経路の設定は[MacからWindowsへRDP接続する](WIREGUARD.md#macからwindowsへrdp接続する)を参照してください。

OCI環境の作成後は、次の順番で実装します。

1. OCI VMとオンプレミスサーバーで、それぞれWireGuard鍵を生成する
2. OCI VMを固定のWireGuard待受側にする
3. オンプレミスサーバーからOCIへ常時接続する
4. WireGuard内で利用するプライベートアドレスを割り当てる
5. OCIの公開ポートを、WireGuard経由でオンプレミスへDNATする
6. 戻り通信の経路とSNATを設定する
7. IPv4、IPv6、TCP、UDPをそれぞれ疎通確認する
8. 必要ならDNSのA/AAAAレコードをTerraformの出力IPへ向ける
   - MyDNS.JPを使う場合は[MyDNS.JPへのIPv4通知](MYDNS.md)を参照する

WireGuard秘密鍵をTerraform変数やstateへ保存すると、stateを読める人が秘密鍵を取得できてしまいます。そのため、鍵生成とWireGuard設定はTerraform stateへ秘密情報を入れない方式で追加します。

## リソースを削除する

OCI環境が不要になった場合は、作成対象を確認してから削除します。

```sh
terraform plan -destroy
terraform destroy
```

このスタックが管理するVM、ネットワーク、予約済みIPv4アドレス、バックアップポリシー、復旧用ブートボリュームも削除されます。必要なデータがVM内に残っていないことを確認してから実行してください。既存のバックアップがOCI側に残る場合もあるため、詳しくは[削除時の注意](BACKUP.md#削除時の注意)を確認してください。
