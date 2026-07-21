# WireGuard中継の管理

このプロジェクトでは、OCIを固定の待受側、Windows 11をOCIへ接続するオンプレミス側Peerとして構成します。

WireGuardの設定ファイルを直接編集せずに運用できるよう、次の2つのスクリプトを用意しています。

- `scripts/wg-relay.sh`: Macから実行する管理コマンド
- `scripts/wg-relay-remote.sh`: OCI上でPeerと`wg0.conf`を管理するコマンド

Windows用秘密鍵は追加・更新コマンドの実行中に生成され、SSHの標準出力からMac上の設定ファイルへ直接保存されます。Terraform state、Git、OCIのディスクには保存しません。

## 管理対象

スクリプトが管理するもの:

- OCI側のWireGuard鍵
- `/etc/wireguard/wg0.conf`
- WindowsなどのPeer追加、更新、削除
- Windowsへインポートできる設定ファイルの生成
- 稼働中のWireGuardへの安全な設定反映
- OCI OSファイアウォールでWireGuard待受ポートを許可
- OCIで受けたTCP/UDPをWindowsへDNAT・SNATする転送ルール

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
