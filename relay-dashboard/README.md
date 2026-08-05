# OCI Relay Control

OCIの公開ポートからWindows MiniPCへの転送経路を、ブラウザから追加・更新・有効化・
無効化する管理画面です。Windows 11のDocker Desktop上で動作し、次の機能をまとめて
反映します。

- TerraformによるOCI Network Security Groupの公開ポート
- `wg-relay`によるOCIからWireGuard PeerへのDNAT・SNAT
- HTTPS Webルート（FQDNからDockerネットワークエイリアスへの振り分け）
- Webルート単位の自動生成Basic認証
- WireGuard Peerの追加・鍵更新・削除
- WireGuard構成ファイルとiPhone向けQRコードの一度限りの発行・ダウンロード
- WireGuard Peer間のTCP/UDPアクセス制御

管理画面はGUIで経路を保存しただけではOCIを変更しません。Terraform planを作成し、内容がOCI NSGの公開ルールだけであることを自動検査した後、確認欄へ`APPLY`と入力した場合だけ反映します。

## セキュリティ設計

このコンテナはTerraformとOCIリレーを操作できる強い権限を持ちます。

- 既定では`127.0.0.1:8081`だけで待ち受ける
- WireGuard経由で公開する場合も、WindowsではWireGuardサブネットとTCP/8081だけを許可する
- Web UIへ到達できるPeerはOCIのPeer間アクセスルールで個別に制御する
- HTTP Basic認証を必須にする
- 状態変更APIへCSRFトークンを要求する
- OCI API鍵とSSH鍵はGit管理対象外にする
- 資格情報ディレクトリはコンテナへ読み取り専用でマウントする
- リポジトリ全体は渡さず、Terraformと管理スクリプトの必要ファイルだけをマウントする
- コンテナ起動時に資格情報をtmpfsへコピーし、`0600`で使用する
- 新規・更新したPeerの秘密鍵はディスクへ保存せず、一度だけブラウザへ返す
- QRコードはコンテナ内でメモリ上の接続設定から生成し、ファイルへ保存しない
- Docker socketはマウントしない
- Traefik APIと証明書Volumeはマウントしない
- Traefik動的設定ディレクトリではマーカー付き`ui-web-routes.yml`だけを更新する
- Webルート用Basic認証の平文パスワードは保存せず、生成時のAPI応答で一度だけ返す
- Basic認証ハッシュはWebルートAPIやプレビューへ表示せず、Traefik専用ファイルへ
  `0600`で保存する
- Linux Capabilityをすべて削除する
- 公開経路のGUI管理ルールには`ui-`を付け、既存の手動公開ルールを保護する
- プロトコル・公開ポート・転送先が完全一致する手動リレールールだけは、planに移管内容を
  表示し、`APPLY`確認後に同等の`ui-`ルールへ置き換える
- Terraform planにNSG公開ルール以外の変更が含まれたらapplyを禁止する

管理画面をインターネットへ直接公開しないでください。

## 管理対象と対象外

管理対象:

- TCP/UDPのOCI公開ポート
- OCIリレーの転送先WireGuardアドレスとポート
- GUI管理経路の追加・更新・有効化・無効化・削除
- TCP/UDPを混在できるポートグループと最大64ポートの一括追加
- WireGuard Peerの追加、状態確認、鍵ローテーション、削除
- WireGuard Peer追加・鍵ローテーション時のQRコードと構成ファイル発行
- Peer間アクセスルールの追加、更新、削除
- Terraform planとapply
- OCIリレー状態、環境チェック、操作履歴
- TCP/80・443のWeb入口下書きとTraefik Webルート

管理対象外:

- Dockerコンテナの起動、更新、Volume、環境変数、ネットワーク接続
- MyDNSのAレコード
- `wg-relay`の初回インストール、初期化、サーバー鍵の再生成
- Windows Firewallの直接変更

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
http://127.0.0.1:8081
```

ユーザー名とパスワードは`relay-dashboard/.env`で確認できます。

`[FATAL tini] exec /app/entrypoint.sh failed: No such file or directory`が表示された場合は、
古いイメージを使わないよう、次のコマンドで再ビルド・再作成します。

```powershell
docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml build --no-cache
docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml up -d --force-recreate
```

## CLIとバックエンドAPI

Web UIの主要な確認、経路登録、Terraform plan/apply、リレー再同期は、同じ認証・検証・
監査を使う非対話CLIからも実行できます。API契約は[openapi.yaml](openapi.yaml)、
全コマンドと例はCLIの`--help`で確認できます。

CLIはコンテナ内で実行すると、既存の`DASHBOARD_USERNAME`と`DASHBOARD_PASSWORD`を
環境から取得します。資格情報を引数、URL、標準出力へ含めません。

```powershell
docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml exec relay-dashboard python3 -m dashboard.cli --json state
docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml exec relay-dashboard python3 -m dashboard.cli --json preflight
```

経路入力はJSONファイルまたは標準入力から渡します。`--dry-run`はバックエンドで入力、
競合、変更件数を検証し、希望状態を変更しません。

```json
{
  "name": "example-app",
  "protocol": "tcp",
  "public_port": 18080,
  "target_address": "10.99.0.2",
  "target_port": 18080,
  "description": "Example"
}
```

```powershell
Get-Content -Raw .\route.json | docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml exec -T relay-dashboard python3 -m dashboard.cli --json route create --input - --dry-run
```

実際に希望状態を保存する場合は、接続先Originの明示確認と冪等性キーが必須です。
同じキー・同じ要求を24時間以内に再試行すると、処理を重複せず保存済みの成功結果を
返します。異なる要求へ同じキーを使うと`409 Conflict`になります。

```powershell
Get-Content -Raw .\route.json | docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml exec -T relay-dashboard python3 -m dashboard.cli --json route create --input - --confirm http://127.0.0.1:8080 --idempotency-key route-example-app-01
docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml exec relay-dashboard python3 -m dashboard.cli --json plan
docker compose --env-file relay-dashboard/.env -f relay-dashboard/compose.yaml exec relay-dashboard python3 -m dashboard.cli --json apply --confirm http://127.0.0.1:8080 --idempotency-key apply-example-app-01
```

成功データは標準出力、`target`、`retryable`、失敗理由を持つJSONエラーは標準エラーへ
分離されます。Terraform成功後にリレーだけ失敗した場合は、APIの`partial`情報から成功済みと
未完了を識別し、復旧後に`sync`コマンドを別の冪等性キーで実行します。

## 5. 最初の経路を作成する

WindowsホストのTCP/41409で待ち受けるMinecraftサーバーへ直接転送する場合:

| 項目 | 値 |
|---|---|
| 経路名 | `minecraft` |
| プロトコル | `TCP` |
| OCI公開ポート | `41409` |
| 転送先アドレス | `10.99.0.2` |
| MiniPCポート | `41409` |

保存後、次の順で操作します。

1. 「環境チェック」ですべて成功することを確認
2. 「変更を確認」でTerraform planを作成
3. 追加・更新・削除・置換の件数を確認
4. 「NSG以外の変更なし」であることを確認
5. 確認欄へ`APPLY`と入力
6. 「OCIへ適用」を選択
7. 「リレー状態」で`ui-minecraft`が希望どおりか確認

Minecraftクライアントには`<OCIを向くホスト名>:41409`を指定します。Traefikやmc-routerは
経由しません。別のMinecraftサーバーは異なる公開ポートとMiniPCポートで経路を追加します。

## Webサービスを公開する

先に[GATEWAY.md](../GATEWAY.md)の手順で`gateway/.env`のACMEメールを設定し、Traefikと
Relay Controlを再作成します。

1. 「Web入口を準備」を選択する
2. 公開経路の「変更を確認」でTCP/80・443だけが追加されることを確認する
3. `APPLY`を入力してOCI NSGとリレーへ反映する
4. 「＋ Webルート」から名前、FQDN、Dockerエイリアス、コンテナポート、説明を保存する
   - 個人データを扱うサービスでは「公開前Basic認証」を有効にする
   - パスワードは自動生成され一度だけ表示されるため、パスワード管理ツールへ保存する
5. 「反映内容を確認」でドメインと転送先、生成設定を確認する
6. `PUBLISH`を入力してTraefikへ反映する
7. MyDNSのAレコードをOCIの予約済みIPv4へ向け、外部回線からHTTPSを確認する

Webルートの保存は下書きです。プレビュー後にルートを変更するとfingerprintが一致しない
ため反映されず、確認をやり直す必要があります。設定ファイルの書き込み途中で失敗した場合は
変更操作をロックし、「Webルートを再反映」で保存済みスナップショットを復旧します。

初期版は1ドメインから1つのHTTPバックエンドだけを扱います。パス振り分け、複数
バックエンド、ワイルドカード、上流HTTPSは対象外です。Relay ControlはDockerサービスを
検出・起動しないため、対象サービスをホスト側Composeで`onprem-relay-ingress`へ接続し、
登録したネットワークエイリアスで到達できるようにしてください。存在しない場合は
`502 Bad Gateway`になります。

WebルートのBasic認証はTraefikでアプリより先に検証し、成功後の`Authorization`
ヘッダーはバックエンドへ転送しません。ユーザー名とパスワードはWebルートごとに独立し、
Relay Control管理画面の資格情報を流用しません。パスワードは256ビット相当の乱数から
自動生成し、Traefikが対応するhtpasswd SHA-1形式のハッシュだけを保存します。
平文パスワードは作成または再生成時に一度だけ返し、操作履歴やWebルートJSONへ保存しません。

MyDNS、コンテナ、Windows FirewallはWeb UIの管理対象外です。現在のIPv4転送を使用し、
AAAAレコードは追加しません。OCIのSNATにより実クライアントIPはバックエンドへ渡りません。

## ポートの一括追加とグループ

「グループ」を選ぶと、TCP/UDPを混在できるポートグループを作成できます。ポート欄は
単一番号、連続範囲、カンマ区切りを組み合わせて指定します。

```text
8000-8015,8080,9000-9002
```

一度に追加できるのは合計64ポートです。公開ポートとMiniPC側の転送先ポートは同じ番号に
なります。異なる番号へ転送する場合は単一経路として追加してください。
グループ名は小文字英数字とハイフンの18文字以内です。重複指定、逆順範囲、範囲外、
予約ポート`22`・`51820`は保存前に拒否されます。

グループ全体のトグルでは、全メンバーをまとめて有効化・無効化できます。一部だけ有効な
グループは「一部有効」と表示され、その状態でグループトグルを選ぶと全メンバーを無効に
します。個別ポートのトグルも使用できます。

グループの見出し部分または右端の`＋`・`−`を選ぶと、ポート一覧とサブグループを
折りたたみ・展開できます。折りたたみ状態はブラウザに保存され、同じ端末・ブラウザで
ダッシュボードを再表示したときも維持されます。

グループの追加・編集画面で親グループを選ぶと、サブグループとして階層表示できます。
親グループのポート件数と有効状態には配下のサブグループも含まれ、親グループのトグルは
配下をまとめて切り替えます。グループを解除した場合、そのグループ直下のポートと
サブグループは1階層上へ移動します。

トグルは希望状態を保存するだけで、直ちにOCIを変更しません。「変更を確認」でplanを
作成し、`APPLY`を入力して適用した後にOCI NSGとリレーの状態が切り替わります。

## 経路の反映状態

経路一覧は「すべて」「有効」「無効」「未反映」「削除済み」のタブで絞り込めます。

| 状態 | 意味 |
|---|---|
| 作成待ち | 新規経路を保存したが、まだApplyしていない |
| 更新待ち | 反映済み経路を編集したが、まだApplyしていない |
| 有効化待ち | 無効な経路を有効にしたが、まだApplyしていない |
| 無効化待ち | 有効な経路を無効にしたが、まだApplyしていない |
| 削除待ち | 削除操作済みだが、OCIとリレーにはまだ残っている |
| リレー同期待ち | Terraformは成功したが、OCIリレー同期が完了していない |
| 有効 | OCI NSGとリレーの両方へ反映されている |
| 無効 | 設定はダッシュボードへ保持され、OCI NSGとリレーでは閉じている |
| 削除済み | OCIとリレーからの削除が両方成功した |

通常は一覧のトグルで無効化します。完全削除は経路編集の「高度な操作」にあり、
誤操作で設定を失わないよう通常の一覧には表示しません。

一度もApplyしていない作成待ち経路を削除すると、作成そのものを取り消します。
反映済み経路を削除すると削除待ちになり、「高度な操作」の「削除待ちを取り消す」で
元に戻せます。
削除待ちのままApplyが成功すると削除済みタブへ移り、設定内容と削除日時が履歴として
無期限に残ります。「高度な操作」の「削除履歴を消去」はOCIやリレーを変更せず、
その履歴だけを完全に消去します。

既存のバージョン1〜3形式の`routes.json`は初回読込時にバージョン4へ自動移行し、
登録済み経路と反映状態を引き継ぎます。移行前データは`routes.json.v1.bak`または
`routes.json.v2.bak`として権限`0600`で一度だけ保存します。アップデート前に削除
された経路は復元できません。

## 7 Days to Dieの例

`7d2d`グループを作り、次の2行を一括登録します。

| プロトコル | ポート指定 | 転送先 |
|---|---|---|
| TCP | `26900` | `10.99.0.2` |
| UDP | `26900-26902` | `10.99.0.2` |

同じ番号のTCPとUDPは別経路として登録できます。

## 適用に失敗した場合

Terraform適用前に失敗した場合、OCIの状態は変更されません。表示された環境チェックまたはplanエラーを解消し、planを作り直します。

Terraform成功後にOCIリレー同期だけ失敗した場合、対象経路は「リレー同期待ち」に
なります。この間は実際の状態と希望状態が混ざらないよう、経路の作成・編集・削除と
Terraform planを停止します。WireGuardとSSHを直した後、「リレーだけ再同期」を選択し、
確認欄へ`SYNC`と入力します。成功すると反映状態が確定し、通常操作を再開できます。

通常時の「リレーだけ再同期」は、最後に正常反映された経路だけをリレーへ復元します。
作成待ち・更新待ち・削除待ちの変更をTerraformより先に適用することはありません。

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

## Web UIでWireGuardを管理する

画面下部の「WireGuard管理」では、OCI上の`wg-relay`へ直接反映されているPeerと
Peer間アクセスプリセットを管理します。公開経路とは異なり、Terraform planや`APPLY`は
使用せず、各操作がOCIへ即時反映されます。

Peer一覧では、WireGuardアドレス、Endpoint、最新ハンドシェイク、通信量、利用を許可した
アクセスプリセットと接続先になっているプリセットを確認できます。

「＋ Peer」でPeer名とアドレスを入力すると、空きアドレスが自動提案され、
接続設定ファイルが一度だけダウンロードされます。接続設定には秘密鍵が含まれるため、
対象端末へ安全に移動してWireGuardへインポートしてください。管理画面やOCIのディスクへ
秘密鍵は保存されません。紛失時は「鍵を更新」で既存鍵を失効させて再発行します。

「＋ プリセット」では、接続先、TCP/UDP、接続先ポートを一度だけ登録します。
Web UIアクセスの場合はMiniPCの`10.99.0.2`とTCP/8081が自動入力されます。
その後、各Peerカードの「プリセット割り当て」で、そのPeerから利用を許可する接続先を
複数選択して一括反映します。3台から5サービスを許可する場合も、接続先プリセットは5件です。
プリセット編集では名前も変更でき、すでに設定済みのPeer割り当てはそのまま維持されます。

Peerを削除する前に、そのPeerのプリセット割り当てをすべて外し、接続先にしている
プリセットを削除してください。OCI側も参照中Peerの削除を拒否します。

## WireGuard経由で管理画面を開くための初期設定

Web UI自身へ初めて接続する経路だけは、Web UIを利用する前に一度だけ設定します。
管理画面を動かすMiniPCを`10.99.0.2`、最初の管理端末を`10.99.0.3`、
管理画面ポートを`8081`とします。初回接続後は管理画面で`dashboard`プリセットを作成し、
追加の管理端末へ再利用できます。

MiniPCの`relay-dashboard/.env`で、公開先をMiniPCのWireGuardアドレスへ変更します。
`0.0.0.0`はLAN側でも待ち受けるため使用しません。

```dotenv
RELAY_DASHBOARD_BIND_IP=10.99.0.2
```

Windows Firewallは管理画面のローカルアドレスとTCP/8081をWireGuardサブネットだけへ
一度許可します。個々のPeerを許可するかどうかはOCI側のアクセスルールで制御します。

```powershell
.\scripts\relay-dashboard-firewall.ps1 add -DashboardClientAddress 10.99.0.0/24
.\scripts\relay-dashboard-firewall.ps1 status
```

最初の管理端末だけはMacなどの管理環境からOCI ACLを追加します。現在の
`mac-admin (10.99.0.3)`では`mac-to-relay-dashboard`ルールを使用します。ルールが
存在しない場合だけ追加してください。

```bash
./scripts/wg-relay.sh peer-forward add mac-to-relay-dashboard --protocol tcp --source-address 10.99.0.3 --target-address 10.99.0.2 --target-port 8081
```

以後のPeer追加とWeb UIアクセス許可は管理画面から実行できます。コンテナを再作成した後、
WireGuard接続中の許可済みPeerから次を開きます。

```powershell
.\scripts\rebuild-relay-dashboard.ps1
```

```text
http://10.99.0.2:8081
```

接続できない場合はWindowsでローカル応答を確認します。

```powershell
Test-NetConnection 10.99.0.2 -Port 8081
```

HTTP Basic認証の内容はWireGuardトンネルで暗号化されます。OCI NSG、自宅ルーター、
LAN側アドレスではTCP/8081を公開しないでください。

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

従来の`public_tcp_ports`と`public_udp_ports`は手動管理用として維持します。
`dashboard_public_tcp_ports`と`dashboard_public_udp_ports`も後方互換用に残します。
管理画面は有効なポートを連続範囲へ圧縮し、次の変数をplan時に渡します。

```hcl
dashboard_public_tcp_port_ranges = [
  {
    min = 8000
    max = 8015
  }
]
dashboard_public_udp_port_ranges = []
```

Terraform内部で手動管理ポートとダッシュボード管理範囲を結合するため、GUI経路を
無効化・削除しても手動管理ポートは消えません。単一ポートのTerraformリソースキーは
従来形式を維持し、連続範囲だけ`8000-8015:0.0.0.0/0`のようなキーを使用します。
連続ポートを1ルールへまとめることで、[OCI NSGの既定上限120ルール](https://docs.oracle.com/en-us/iaas/Content/General/service-limits/default.htm)
を消費しにくくします。

ただし、同じプロトコル・公開ポートを手動ルールとGUIルールの両方へ割り当てることは
できません。管理画面はOCIリレーの既存ルールを確認し、転送先まで完全一致する場合は
plan画面に移管対象を表示します。`APPLY`すると手動ルールを削除し、同じ転送内容の
`ui-`ルールとして再作成するため、以後は管理画面から有効化・無効化・編集できます。
転送先が異なる場合は従来どおり競合としてplanを停止します。
