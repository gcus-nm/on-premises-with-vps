# MyDNS.JPへのIPv4通知

このプロジェクトでは、MyDNS.JPのChild IDを使って、OCI中継サーバーの予約済み
パブリックIPv4アドレスを次のようなホスト名へ通知できます。

```text
aaa.mydns.jp      -> 自宅IP（MasterID）
oci.aaa.mydns.jp  -> OCI予約済みIPv4（Child ID）
```

通知はOCI VM自身からHTTPSで行います。Child IDとパスワードはOCI VM内のroot専用
ファイルだけに保存し、Git、Terraform変数、Terraform state、ローカル端末には保存
しません。

## 前提

- MyDNS.JPでChild IDを作成済みであること
- `DOMAIN INFO`で`oci`をChild IDへ割り当て済みであること
  - 配下のゾーンもChild IDで管理する場合は`TYPE = DELEGATE`
- `~/.ssh/config`の`oci-relay`でOCI VMへ接続できること
- OCI VMからインターネットへHTTPS接続できること

MyDNS.JPは、異なるグローバルIPをサブドメインへ割り当てる場合にChild IDを使用する
方法を案内しています。

- [MyDNS.JP How to Use](https://www.mydns.jp/?MENU=020)

## 1. 通知コマンドとsystemd timerをインストールする

リポジトリのルートで実行します。

```bash
./scripts/mydns-notify.sh install
```

次のファイルをOCI VMへ配置します。

```text
/usr/local/sbin/mydns-notify
/etc/systemd/system/mydns-notify.service
/etc/systemd/system/mydns-notify.timer
```

この時点では認証情報を作成せず、timerの有効・無効状態も変更しません。

## 2. Child IDを設定する

実際のホスト名を指定して実行します。

```bash
./scripts/mydns-notify.sh configure oci.aaa.mydns.jp
```

SSH接続先でChild IDとパスワードを対話入力します。パスワードは画面に表示されません。
設定後、通知を一度実行してMyDNS.JPの成功応答を確認してから、日次timerを有効化
します。

認証情報はOCI VM上の次のファイルへ保存されます。

```text
/etc/mydns-notify/config.json
```

所有者は`root`、権限は`600`です。このファイルをリポジトリへコピーしないでください。

## 3. 状態を確認する

設定、現在のAレコード、timerの次回実行時刻を確認します。

```bash
./scripts/mydns-notify.sh status
```

任意のタイミングで通知を実行できます。

```bash
./scripts/mydns-notify.sh notify
```

systemdログを確認します。

```bash
./scripts/mydns-notify.sh logs
```

ローカル端末からDNS応答を直接確認する場合:

```bash
dig +short oci.aaa.mydns.jp A
```

Terraformの出力と一致することも確認します。

```bash
terraform output -raw public_ipv4
```

DNSキャッシュや伝播により、通知直後は以前のアドレスが返る場合があります。

## 実行間隔

`mydns-notify.timer`は、起動5分後と毎日1回に実行します。日次実行には最大30分の
ランダム遅延を加え、MyDNS.JPへ同時刻にアクセスが集中しないようにしています。
停止中に日次実行を逃した場合は、次回起動後に補完します。

MyDNS.JPは最後のIP通知またはログインから1週間を超えるとDNS情報を停止対象とし、
1か月以上通知もログインもない場合は登録情報を削除すると案内しています。

- [MyDNS.JPの通知方法と保持期間](https://www.mydns.jp/?MENU=200)

## Child IDのパスワードを変更した場合

同じconfigureコマンドを再実行すると、root専用設定を安全に置き換え、直後に通知を
検証します。

```bash
./scripts/mydns-notify.sh configure oci.aaa.mydns.jp
```

## 別のSSH Hostを使う場合

`oci-relay`以外のSSH Hostを利用する場合は、コマンドごとに指定できます。

```bash
MYDNS_NOTIFY_SSH_HOST=別名 ./scripts/mydns-notify.sh status
```
