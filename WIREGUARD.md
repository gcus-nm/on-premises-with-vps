# WireGuard中継の管理

このプロジェクトでは、OCIを固定の待受側、Windows 11をOCIへ接続するオンプレミス側Peerとして構成します。

WireGuardの設定ファイルを直接編集せずに運用できるよう、次の2つのスクリプトを用意しています。

- `scripts/wg-relay.sh`: Macから実行する管理コマンド
- `scripts/wg-relay-remote.sh`: OCI上でPeerと`wg0.conf`を管理するコマンド

初期構築後は[OCI Relay Control](relay-dashboard/README.md)の「WireGuard管理」から、
Peerの追加・鍵更新・削除、iPhone向けQRコードと構成ファイルの一度限りの発行、
Peer間アクセスルールも操作できます。最初に管理画面へ接続する
ためのACLだけは、このスクリプトから設定します。

Windows用秘密鍵は追加・更新コマンドの実行中に生成され、SSHの標準出力からMac上の設定ファイルへ直接保存されます。Terraform state、Git、OCIのディスクには保存しません。

## iPhone用Peerを管理画面から発行する

1. OCI Relay Controlの「WireGuard管理」で「＋ Peer」を選択する
2. 端末名（例: `iphone-gcus`）を入力し、自動提案された空きアドレスを確認する
3. 「追加して発行」を選択する
4. iPhoneのWireGuardアプリで「＋」からQRコードによる作成を選び、表示されたQRを読む
5. 同じiPhoneで管理画面を開いている場合は、`.conf`をダウンロードしてWireGuardへ読み込む

QRコードと`.conf`にはクライアント秘密鍵が含まれます。管理画面はどちらも保存せず、
発行レスポンスで一度だけ表示します。画面を閉じた後の再ダウンロードはできません。
紛失時はPeer一覧の「設定を再発行」で鍵をローテーションしてください。以前の設定は
直ちに接続できなくなります。ダウンロードしたQRや`.conf`は安全な場所で管理し、
端末への登録後に不要なら削除してください。

## 管理対象

スクリプトが管理するもの:

- OCI側のWireGuard鍵
- `/etc/wireguard/wg0.conf`
- WindowsなどのPeer追加、更新、削除
- Windowsへインポートできる設定ファイルの生成
- 稼働中のWireGuardへの安全な設定反映
- OCI OSファイアウォールでWireGuard待受ポートを許可
- OCIで受けたTCP/UDPをWindowsへDNAT・SNATする転送ルール
- WireGuard Peer間で許可するプロトコルとポートのACL

スクリプトが管理しないもの:

- OCI NSGの公開ポート。Terraformで管理します。
- OCI NSGでゲームポートを許可するTerraform変数
- Windowsへの設定ファイルのインポート操作
- Docker Composeのポート設定

## 前提

- `~/.ssh/config`の`oci-relay`でOCIへ接続できること
- OCIにWireGuardがインストールされていること
- Terraformのリモートstateを読み取れること

別のSSH Hostを利用する場合は環境変数で指定できます。

```bash
WG_RELAY_SSH_HOST=別名 ./scripts/wg-relay.sh status
```

## 1. OCIへ管理コマンドをインストールする

リポジトリのルートで実行します。

```bash
./scripts/wg-relay.sh install
```

この操作では`/usr/local/sbin/wg-relay`を配置するだけで、WireGuardの設定や稼働状態は変更しません。

## 2. OCIを待受側として初期化する

```bash
./scripts/wg-relay.sh init
```

既定値は次のとおりです。

- OCIトンネルアドレス: `10.99.0.1/24`
- WireGuard待受ポート: `51820/udp`
- 公開Endpoint: `terraform output wireguard_endpoint_ipv4`の値

明示する場合:

```bash
./scripts/wg-relay.sh init \
  --server-address 10.99.0.1/24 \
  --listen-port 51820 \
  --endpoint 161.33.162.42:51820
```

すでにOCI上に`private.key`と`public.key`がある場合は再利用します。既存の`wg0.conf`がスクリプト管理外の場合は、上書きせずエラーで停止します。

## 3. Windows Peerを追加する

```bash
./scripts/wg-relay.sh add windows-minibox --address 10.99.0.2/32
```

成功すると、Windowsへインポートする設定が次の場所へ作成されます。

```text
generated/wireguard/windows-minibox.conf
```

ファイル権限は`600`です。このディレクトリはGit管理対象外です。

WireGuard for Windowsで「トンネルをファイルからインポート」を選び、このファイルを読み込んで有効化します。

## 4. 状態を確認する

登録済みPeer:

```bash
./scripts/wg-relay.sh list
```

WireGuardの稼働状態とハンドシェイク:

```bash
./scripts/wg-relay.sh status
```

OCI側公開鍵:

```bash
./scripts/wg-relay.sh public-key
```

TCP/UDP転送ルール:

```bash
./scripts/wg-relay.sh forward list
./scripts/wg-relay.sh forward status
```

Peer間通信ルール:

```bash
./scripts/wg-relay.sh peer-forward list
./scripts/wg-relay.sh peer-forward status
```

Windowsでトンネルを有効にした後、Windows PowerShellから確認します。

```powershell
ping 10.99.0.1
```

## 5. Peerを更新する

```bash
./scripts/wg-relay.sh update windows-minibox --address 10.99.0.2/32
```

更新時はWindows側の鍵をローテーションし、新しい設定ファイルで既存ファイルを置き換えます。コマンド完了後、WireGuard for Windowsへ新しい設定を再インポートしてください。古いWindows設定では接続できなくなります。

別の出力先を指定できます。

```bash
./scripts/wg-relay.sh update windows-minibox \
  --address 10.99.0.2/32 \
  --output ~/Downloads/windows-minibox.conf
```

## 6. Peerを削除する

```bash
./scripts/wg-relay.sh delete windows-minibox
```

確認なしで削除する場合:

```bash
./scripts/wg-relay.sh delete windows-minibox --yes
```

削除後、Macに保存したWindows用設定ファイルと、WireGuard for Windowsへ登録したトンネルも削除してください。ローカルの設定ファイルは秘密鍵を含むため、不要になった時点で安全に削除します。

## 設定の保存場所

OCI側:

```text
/etc/wireguard/private.key
/etc/wireguard/public.key
/etc/wireguard/wg0.conf
/etc/wireguard/relay.d/settings
/etc/wireguard/relay.d/peers/<Peer名>.conf
```

Mac側:

```text
generated/wireguard/<Peer名>.conf
```

`wg0.conf`とPeer断片は直接編集しないでください。変更は必ず`wg-relay.sh`から行います。

OCIの転送ルールは次へ保存され、WireGuard起動時に自動反映されます。

```text
/etc/wireguard/relay.d/forwards/<転送名>.conf
```

具体的な追加方法は[Docker入口とゲームポート転送](GATEWAY.md)を参照してください。

## 障害時

追加・更新・削除に失敗した場合、OCI側スクリプトは変更前のPeer設定へ戻し、稼働中のWireGuardへ再反映します。

状態確認:

```bash
ssh oci-relay sudo /usr/local/sbin/wg-relay status
```

systemdログ:

```bash
ssh oci-relay sudo journalctl -u wg-quick@wg0 --no-pager -n 100
```

Windowsから`ping 10.99.0.1`がタイムアウトする場合は、まずハンドシェイクを確認します。

```bash
./scripts/wg-relay.sh status
```

`latest handshake`が表示されない場合は、Windows側でトンネルが有効か、OCIのNSGとOSファイアウォールの両方でWireGuardのUDP待受ポートが許可されているかを確認してください。管理スクリプトを更新した直後は、`install`と`init`を再実行するとOSファイアウォール設定も反映されます。既存のPeerと鍵は維持されます。

## Peer間アクセスプリセットを使う

`peer-forward`は、接続先とポートを1つのプリセットとして保存し、複数の接続元Peerを
割り当てられます。管理画面への接続先を先に登録する例です。

```bash
./scripts/wg-relay.sh peer-forward add dashboard --protocol tcp --target-address 10.99.0.2 --target-port 8081
```

`10.99.0.3`から使うプリセット一式を割り当てます。`assign-source`は指定した接続元Peerの
割り当て全体を置き換えるため、複数使う場合はプリセット名をすべて列挙します。

```bash
./scripts/wg-relay.sh peer-forward assign-source 10.99.0.3 dashboard
```

`10.99.0.5`にも同じプリセットを割り当てる場合、プリセット自体の再作成は不要です。

```bash
./scripts/wg-relay.sh peer-forward assign-source 10.99.0.5 dashboard
```

旧形式の`SOURCE_ADDRESS`を持つ設定は引き続き読み込まれ、更新または割り当て変更時に
複数接続元の`SOURCE_ADDRESSES`形式へ移行します。

## MacからWindowsへRDP接続する

Macを`10.99.0.3`、Windowsを`10.99.0.2`としている場合の例です。RDPはWireGuard内だけで転送するため、OCI NSG、自宅ルーター、Windowsの物理LAN側でTCP/3389やUDP/3389を一般公開する必要はありません。

管理スクリプトをOCIへ更新します。この操作だけでは既存ルールを変更しません。

```bash
./scripts/wg-relay.sh install
```

MacからWindowsへのRDPをTCPとUDPで許可します。

```bash
./scripts/wg-relay.sh peer-forward add mac-to-windows-rdp-tcp \
  --protocol tcp \
  --source-address 10.99.0.3 \
  --target-address 10.99.0.2 \
  --target-port 3389

./scripts/wg-relay.sh peer-forward add mac-to-windows-rdp-udp \
  --protocol udp \
  --source-address 10.99.0.3 \
  --target-address 10.99.0.2 \
  --target-port 3389
```

確認:

```bash
./scripts/wg-relay.sh peer-forward list
./scripts/wg-relay.sh peer-forward status
```

今後生成するクライアント設定は、Peer間の経路を含む次の値になります。

```ini
AllowedIPs = 10.99.0.0/24
```

すでにMacとWindowsへインポート済みの設定が`10.99.0.1/32`の場合は、両方のWireGuardアプリで`AllowedIPs`を`10.99.0.0/24`へ変更してトンネルを再度有効にします。サーバー側のPeer設定や鍵の変更は不要です。

Windows 11 Proでリモートデスクトップを有効にし、管理者PowerShellでWireGuard上のMacだけを許可します。

```powershell
New-NetFirewallRule `
  -DisplayName "RDP over WireGuard TCP" `
  -Direction Inbound -Action Allow `
  -Protocol TCP -LocalPort 3389 `
  -RemoteAddress 10.99.0.3 -Profile Any

New-NetFirewallRule `
  -DisplayName "RDP over WireGuard UDP" `
  -Direction Inbound -Action Allow `
  -Protocol UDP -LocalPort 3389 `
  -RemoteAddress 10.99.0.3 -Profile Any
```

MacからTCP到達性を確認します。

```bash
nc -vz 10.99.0.2 3389
```

到達できたら、MacのRDPクライアントで`10.99.0.2`へ接続します。

ルールの転送先などを変更する場合は`update`を使用します。削除時は確認が表示されます。

```bash
./scripts/wg-relay.sh peer-forward update mac-to-windows-rdp-tcp \
  --protocol tcp \
  --source-address 10.99.0.3 \
  --target-address 10.99.0.2 \
  --target-port 3389

./scripts/wg-relay.sh peer-forward delete mac-to-windows-rdp-tcp
./scripts/wg-relay.sh peer-forward delete mac-to-windows-rdp-udp
```

Peer間アクセスプリセットはOCIの次の場所へ保存され、WireGuardやVMの再起動、通常のポート転送更新後も`firewall-sync`によって再適用されます。

```text
/etc/wireguard/relay.d/peer-forwards/<ルール名>.conf
```

プリセットから参照中のPeerは削除できません。接続元の割り当てを外すか、接続先にしている
`peer-forward`を先に削除してください。
