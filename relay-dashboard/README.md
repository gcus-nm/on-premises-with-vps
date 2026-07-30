# OCI Relay Control

OCIの公開ポートからWindows MiniPCへの転送経路を、ブラウザから追加・更新・削除する管理画面です。Windows 11のDocker Desktop上で動作し、次の2つをまとめて反映します。

- TerraformによるOCI Network Security Groupの公開ポート
- `wg-relay`によるOCIからWireGuard PeerへのDNAT・SNAT

管理画面はGUIで経路を保存しただけではOCIを変更しません。Terraform planを作成し、内容がOCI NSGの公開ルールだけであることを自動検査した後、確認欄へ`APPLY`と入力した場合だけ反映します。

## セキュリティ設計

このコンテナはTerraformとOCIリレーを操作できる強い権限を持ちます。

- 既定では`127.0.0.1:41800`だけで待ち受ける
- HTTP Basic認証を必須にする
- 状態変更APIへCSRFトークンを要求する
- OCI API鍵とSSH鍵はGit管理対象外にする
- 資格情報ディレクトリはコンテナへ読み取り専用でマウントする
- リポジトリ全体は渡さず、Terraformと管理スクリプトの必要ファイルだけをマウントする
- コンテナ起動時に資格情報をtmpfsへコピーし、`0600`で使用する
- Docker socketはマウントしない
- Linux Capabilityをすべて削除する
- GUI管理ルールには`ui-`を付け、既存の手動ルールを削除しない
- Terraform planにNSG公開ルール以外の変更が含まれたらapplyを禁止する

管理画面をインターネットへ直接公開しないでください。

## 管理対象と対象外

管理対象:

- TCP/UDPのOCI公開ポート
- OCIリレーの転送先WireGuardアドレスとポート
- GUI管理経路の追加・更新・削除
- Terraform planとapply
- OCIリレー状態、環境チェック、操作履歴

管理対象外:

- Dockerコンテナ自身のポート公開
- MyDNSのAレコード
- Minecraftのmc-routerホスト名マッピング
- WireGuard Peerの作成
- Windows FirewallのGUIからの直接変更

ゲームコンテナがWindowsホストへ対象ポートを公開していることは、事前に`docker ps`で確認してください。

## 1. 前提を確認する

WindowsでWireGuardの`windows-minibox`トンネルを有効にします。

```powershell
ping 10.99.0.1
```

応答があることを確認します。

MiniPC側のリポジトリルートに`terraform.tfvars`が必要です。このファイルはGit管理対象外なので、Macで使用しているファイルを安全な方法でコピーしてください。OCI API秘密鍵とSSH秘密鍵もMiniPCへ安全に用意します。

## 2. 資格情報とログイン設定を準備する

MiniPCのPowerShellでリポジトリルートへ移動し、セットアップスクリプトを実行します。

```powershell
.\relay-dashboard\setup.ps1
```

既定では次のファイルを読み取ります。

```text
%USERPROFILE%\.oci\config
%USERPROFILE%\.ssh\oci-relay
```

別の場所にある場合:

```powershell
.\relay-dashboard\setup.ps1 `
  -OciConfigPath "C:\secure\oci\config" `
  -OciPrivateKeyPath "C:\secure\oci\oci_api_key.pem" `
  -SshPrivateKeyPath "C:\secure\ssh\oci-relay"
```

OCI設定には`DEFAULT`プロファイルと次の5項目が必要です。値はOCIコンソールと、
登録済みAPI秘密鍵の配置先に合わせます。

```ini
[DEFAULT]
tenancy=ocid1.tenancy.oc1..（テナンシーOCID）
user=ocid1.user.oc1..（ユーザーOCID）
fingerprint=（APIキーのフィンガープリント）
region=ap-tokyo-1
key_file=C:\Users\ユーザー名\.oci\relay-dashboard-api-key.pem
```

セットアップスクリプトは値を画面へ表示せず、`DEFAULT`に必須項目が揃っているか
検査します。空の設定ファイルや別プロファイルだけの設定は受け付けません。

スクリプトは次を実行します。

1. OCI設定と秘密鍵を`relay-dashboard/secrets/oci`へコピー
2. SSH設定と秘密鍵を`relay-dashboard/secrets/ssh`へコピー
3. `10.99.0.1`のSSHホスト鍵を取得し、既知のフィンガープリントと照合
4. ランダムな管理画面パスワードを生成して`relay-dashboard/.env`へ保存

`relay-dashboard/.env`と`relay-dashboard/secrets`はGit管理対象外です。

Windows版`ssh-keyscan`が鍵を返さない場合は、通常のSSH接続で登録済みの
`$HOME\.ssh\known_hosts`から`10.99.0.1`のED25519鍵を取得します。どちらの経路でも、
既知のフィンガープリントと一致しない鍵は保存しません。

## 3. Windows Firewallを一度だけ設定する

管理者として起動したPowerShellで実行します。

```powershell
.\scripts\relay-dashboard-firewall.ps1 add
.\scripts\relay-dashboard-firewall.ps1 status
```

このルールは、WireGuardアドレス`10.99.0.1`から`10.99.0.2`へ届くTCP/UDPだけを許可します。自宅LANやインターネット全体からの受信は許可しません。

削除する場合:

```powershell
.\scripts\relay-dashboard-firewall.ps1 remove
```

## 4. Dockerで起動する

```powershell
docker compose `
  --env-file relay-dashboard/.env `
  -f relay-dashboard/compose.yaml `
  config

docker compose `
  --env-file relay-dashboard/.env `
  -f relay-dashboard/compose.yaml `
  build

docker compose `
  --env-file relay-dashboard/.env `
  -f relay-dashboard/compose.yaml `
  up -d

docker compose `
  --env-file relay-dashboard/.env `
  -f relay-dashboard/compose.yaml `
  ps
```

ブラウザで次を開きます。

```text
http://127.0.0.1:41800
```

ユーザー名とパスワードは`relay-dashboard/.env`で確認できます。

`[FATAL tini] exec /app/entrypoint.sh failed: No such file or directory`が表示された場合は、
古いイメージを使わないよう、次のコマンドで再ビルド・再作成します。

```powershell
docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml build --no-cache
docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml up -d --force-recreate
```

## 5. 最初の経路を作成する

Minecraft共通入口の場合:

| 項目 | 値 |
|---|---|
| 経路名 | `minecraft` |
| プロトコル | `TCP` |
| OCI公開ポート | `25565` |
| 転送先アドレス | `10.99.0.2` |
| MiniPCポート | `25565` |

保存後、次の順で操作します。

1. 「環境チェック」ですべて成功することを確認
2. 「変更を確認」でTerraform planを作成
3. 追加・更新・削除・置換の件数を確認
4. 「NSG以外の変更なし」であることを確認
5. 確認欄へ`APPLY`と入力
6. 「OCIへ適用」を選択
7. 「リレー状態」で`ui-minecraft`が希望どおりか確認

Minecraftのサブドメイン振り分けは、従来どおり`mc-route.ps1`で設定します。GUIのTCP/25565経路は、その手前のOCI公開入口を担当します。

## 7 Days to Dieの例

次の4経路を登録します。

| 経路名 | プロトコル | OCI公開 | MiniPC |
|---|---|---:|---:|
| `7d2d-tcp` | TCP | 26900 | 26900 |
| `7d2d-udp-main` | UDP | 26900 | 26900 |
| `7d2d-udp-plus-1` | UDP | 26901 | 26901 |
| `7d2d-udp-plus-2` | UDP | 26902 | 26902 |

同じ番号のTCPとUDPは別経路として登録できます。

## 適用に失敗した場合

Terraform適用前に失敗した場合、OCIの状態は変更されません。表示された環境チェックまたはplanエラーを解消し、planを作り直します。

Terraform成功後にOCIリレー同期だけ失敗した場合、NSGの公開ポートは開いていますが、転送ルールがないためMiniPCへ通信は届きません。WireGuardとSSHを直した後、「リレーだけ再同期」を選択し、確認欄へ`SYNC`と入力します。

GUI以外で確認する場合:

```powershell
docker compose `
  --env-file relay-dashboard/.env `
  -f relay-dashboard/compose.yaml `
  logs --tail 200 relay-dashboard
```

Mac側管理スクリプトからも確認できます。

```bash
./scripts/wg-relay.sh forward list
./scripts/wg-relay.sh forward status
```

## Macから管理画面を開く場合

既定の`127.0.0.1`はMiniPC自身からだけアクセスできます。MacのWireGuardアドレスが`10.99.0.3`の場合、`relay-dashboard/.env`を次のように変更します。

```dotenv
RELAY_DASHBOARD_BIND_IP=0.0.0.0
```

管理者PowerShellで管理画面ポートだけをMacへ許可します。

```powershell
New-NetFirewallRule `
  -DisplayName "Relay Dashboard from Mac" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalAddress 10.99.0.2 `
  -LocalPort 41800 `
  -RemoteAddress 10.99.0.3 `
  -Profile Any
```

コンテナを再作成した後、Macから次を開きます。

```text
http://10.99.0.2:41800
```

HTTP Basic認証の内容はWireGuardトンネルで暗号化されます。LANやインターネットへ同じポートを公開しないでください。

## 停止とデータ

停止:

```powershell
docker compose `
  --env-file relay-dashboard/.env `
  -f relay-dashboard/compose.yaml `
  down
```

経路、操作履歴、Terraform ProviderキャッシュとProvider取得時の一時ファイルは
`onprem-relay-dashboard-data`ボリュームへ保存されます。OCI・SSH資格情報は
コンテナ起動ごとにtmpfsへコピーされ、コンテナ停止時に消えます。

次の操作は管理画面データを削除するため、通常は実行しないでください。

```powershell
docker compose `
  --env-file relay-dashboard/.env `
  -f relay-dashboard/compose.yaml `
  down -v
```

## Terraformとの共存

従来の`public_tcp_ports`と`public_udp_ports`は手動管理用として維持します。管理画面は別の次の変数をplan時に渡します。

```hcl
dashboard_public_tcp_ports = []
dashboard_public_udp_ports = []
```

Terraform内部で両方を集合結合するため、GUI経路を削除しても手動管理ポートは消えません。

ただし、同じプロトコル・公開ポートを手動ルールとGUIルールの両方へ割り当てることはできません。管理画面はOCIリレーの既存ルールを確認し、競合時にはplanを停止します。
