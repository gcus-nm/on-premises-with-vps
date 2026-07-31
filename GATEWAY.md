# Docker入口とゲームポート転送

この構成では、OCIをIPv4の公開入口、Windows 11のDocker Desktopをサービス実行環境として使用します。

公開経路を頻繁に追加・更新・削除する場合は、Terraformと`wg-relay forward`をブラウザから一元管理できる[OCI Relay Control](relay-dashboard/README.md)を利用できます。この文書の手動コマンドは、管理画面を使わない場合や障害調査時にも引き続き使用できます。

```text
インターネット
  ↓
OCI Network Security Group
  ↓
OCI wg-relay（DNAT + SNAT）
  ↓ WireGuard
Windows 10.99.0.2
  ↓
Traefik → mc-routerまたは各ゲームコンテナ
```

WebはTraefikがHTTPSのHTTP Host名で振り分け、TCP/80へのアクセスは443へ転送します。
証明書はLet's Encrypt HTTP-01で自動取得します。Minecraft Javaはmc-routerがMinecraft
クライアントの接続先ホスト名で振り分けます。一般的なTCP/UDPゲームは、ゲーム固有の
公開ポートごとにTraefikから対象コンテナへ転送します。

## 初期構成

リポジトリの`gateway`ディレクトリには次の入口を用意しています。

- TCP/80: Let's Encrypt HTTP-01とHTTPSリダイレクト
- TCP/443: HTTPS Web用Traefik EntryPoint
- TCP/25565: Traefikからmc-routerへ転送
- mc-routerからWindowsホスト上の各Minecraft公開ポートへ転送

Minecraftのマッピング例:

| 接続先ホスト名 | Windowsホスト上の転送先 |
|---|---:|
| `minecraft.<MyDNSドメイン>` | TCP/41409 |
| `minecraft-hardcore.<MyDNSドメイン>` | TCP/41411 |

ホスト名にはアンダースコアではなくハイフンを使用してください。

実際のマッピングはGit管理対象外の`gateway/mc-router/routes.json`へ保存します。PowerShell管理コマンドから追加・更新・削除でき、mc-routerが変更を自動的に再読み込みします。

この構成では、mc-router公式の[`ROUTES_CONFIG`と`ROUTES_CONFIG_WATCH`](https://github.com/itzg/mc-router#routing-configuration)を使用します。

## 1. Windowsで入口設定を準備する

PowerShellでリポジトリのルートへ移動し、Compose用環境変数を準備します。

```powershell
if (-not (Test-Path gateway\.env)) {
  Copy-Item gateway\.env.example gateway\.env
}
notepad gateway\.env
```

`TRAEFIK_ACME_EMAIL`を実際に受信できる連絡先へ変更してください。本番のLet's Encryptが
既定です。構築中に繰り返し証明書取得を試す場合は、`gateway/.env`で次を有効にします。
staging証明書はブラウザに信頼されないため、疎通確認後は行を削除またはコメントアウトし、
Traefikを再作成してください。

```dotenv
TRAEFIK_ACME_EMAIL=admin@example.jp
TRAEFIK_ACME_CA_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory
TRAEFIK_CERTIFICATES_VOLUME=onprem-relay-traefik-certificates-staging
```

本番へ切り替えるときは、CA Serverとstaging用Volumeの2行を両方削除またはコメントアウト
します。これによりstaging証明書を本番用Volumeへ持ち込まず、既定の
`onprem-relay-traefik-certificates`へ本番証明書を保存します。

Minecraftのルートを登録します。`set`は、ホスト名が未登録なら追加、登録済みなら転送先を更新します。

```powershell
.\scripts\mc-route.ps1 set `
  minecraft.example.mydns.jp `
  host.docker.internal:41409

.\scripts\mc-route.ps1 set `
  minecraft-hardcore.example.mydns.jp `
  host.docker.internal:41411

.\scripts\mc-route.ps1 list
```

`gateway/.env`と`gateway/mc-router/routes.json`はGit管理対象外です。マッピングのJSONを直接編集する必要はありません。

既存MinecraftコンテナがWindowsホストの41409と41411へ公開されていることを確認します。

```powershell
docker ps --format "table {{.Names}}\t{{.Ports}}"
```

mc-routerはDocker Desktopの`host.docker.internal`を通して、この2ポートへ接続します。

## 2. Windowsで入口コンテナを起動する

リポジトリのルートで実行します。

```powershell
docker compose --env-file gateway/.env -f gateway/compose.yaml config
docker compose --env-file gateway/.env -f gateway/compose.yaml pull
docker compose --env-file gateway/.env -f gateway/compose.yaml up -d
docker compose --env-file gateway/.env -f gateway/compose.yaml ps
```

Compose引数やACME設定を変更した後は、再起動ではなくTraefikを再作成します。

```powershell
docker compose --env-file gateway/.env -f gateway/compose.yaml up -d --force-recreate traefik
```

証明書とACMEアカウントは`onprem-relay-traefik-certificates`という専用Docker Volumeへ
保存され、Relay Controlにはマウントされません。通常のコンテナ再作成やイメージ更新では
Volumeを削除しないでください。

```powershell
docker volume inspect onprem-relay-traefik-certificates
```

Volumeを削除すると証明書を再取得するため、Let's Encryptのレート制限に達する可能性が
あります。破損時の初期化が必要な場合だけ、Traefikを停止し、Volume名を再確認したうえで
手動削除してください。

## WebサービスをRelay Controlから登録する

Relay Controlの「Webサービス」で次の順に操作します。

1. 「Web入口を準備」でTCP/80・443のOCI経路を下書きする
2. 公開経路の「変更を確認」でTerraform planを確認し、`APPLY`で反映する
3. WebルートへFQDN、Dockerネットワークエイリアス、コンテナポートを保存する
4. 「反映内容を確認」で生成設定を確認し、`PUBLISH`でTraefikへ反映する
5. MyDNSのAレコードをOCIの予約済みIPv4へ向ける

Webルートの保存だけではTraefikを変更しません。Relay Controlが更新するのは
`gateway/traefik/dynamic/ui-web-routes.yml`だけです。同じディレクトリにあるMinecraftや
ゲーム用の設定ファイルには触れません。

各WebサービスのComposeでは、外部ネットワークへ安定したエイリアスを付けます。
Traefikからバックエンドへの通信はHTTPで、ホストへの`ports`公開は不要です。

```yaml
services:
  app:
    image: example/app:1.0
    expose:
      - "8080"
    networks:
      relay-ingress:
        aliases:
          - app-service

networks:
  relay-ingress:
    external: true
    name: onprem-relay-ingress
```

Relay Controlはコンテナの存在確認、起動、更新、Volume、環境変数を管理しません。
エイリアスが存在しない、またはサービスが停止している場合は`502 Bad Gateway`になります。

ログ確認:

```powershell
docker compose --env-file gateway/.env -f gateway/compose.yaml logs --tail 100 traefik mc-router
```

## Minecraftルートを運用する

コンテナ起動後も、同じ管理コマンドでマッピングを変更できます。mc-routerが`routes.json`を監視しているため、通常はコンテナの再起動は不要です。

追加または転送先更新:

```powershell
.\scripts\mc-route.ps1 set `
  minecraft-beta.example.mydns.jp `
  host.docker.internal:41413
```

一覧:

```powershell
.\scripts\mc-route.ps1 list
```

削除:

```powershell
.\scripts\mc-route.ps1 remove minecraft-beta.example.mydns.jp
```

変更後はログで再読み込みを確認します。

```powershell
docker compose --env-file gateway/.env -f gateway/compose.yaml logs --tail 100 mc-router
```

ファイル監視が反映されない場合に限り、mc-routerを再起動します。

```powershell
docker compose --env-file gateway/.env -f gateway/compose.yaml restart mc-router
```

Windows Defender Firewallで確認を求められた場合は、パブリックネットワーク全体ではなく、WireGuard経由で必要な受信だけを許可してください。

## 3. TerraformでOCIの公開ポートを許可する

Mac側の`terraform.tfvars`へTCP/25565を追加します。Webを公開するときだけ80と443も追加します。

```hcl
public_tcp_ports = [25565]
public_udp_ports = []
```

変更内容を確認して適用します。

```bash
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

## 4. OCIからWindowsへ転送する

Mac側のリポジトリルートで実行します。

```bash
./scripts/wg-relay.sh forward add minecraft \
  --protocol tcp \
  --listen-port 25565 \
  --target-address 10.99.0.2 \
  --target-port 25565
```

このルールは次の変換を行います。

```text
OCI TCP/25565 → Windows TCP/25565 → Traefik → mc-router → TCP/41409または41411
```

DNATに加えてSNATも行うため、Windowsからの返信は自宅回線ではなくWireGuardへ戻ります。代わりに、Windows側とゲームコンテナから見える接続元IPはOCIのトンネルIP`10.99.0.1`になります。

確認:

```bash
./scripts/wg-relay.sh forward list
./scripts/wg-relay.sh forward status
./scripts/wg-relay.sh status
```

## 5. MyDNSをOCIへ向ける

次のAレコードをOCIの予約済みIPv4へ向けます。

```text
minecraft.example.mydns.jp          A  161.33.162.42
minecraft-hardcore.example.mydns.jp A  161.33.162.42
```

現在の転送実装はIPv4用なので、AAAAレコードは追加しないでください。MyDNSのIP通知を利用する場合も、自宅のIPv4ではなくOCIの予約済みIPv4が登録されるようにします。

DNS反映後、家庭内LANとは別の回線から次の2つをMinecraft Javaへ登録して確認します。

```text
minecraft.example.mydns.jp
minecraft-hardcore.example.mydns.jp
```

## 一般的なTCP/UDPゲームを追加する

新しいゲームは次の3層へ同じ公開ポートを追加します。

1. Windows入口ComposeのTraefik EntryPoint
2. Terraformの`public_tcp_ports`または`public_udp_ports`
3. OCIの`wg-relay forward`

### 7 Days to Dieの例

`gateway/traefik/examples/7d2d.yml`を`gateway/traefik/dynamic/7d2d.yml`へコピーします。

`gateway/compose.yaml`のTraefik `command`へEntryPointを追加します。

```yaml
command:
  - --entryPoints.seven-days-to-die-tcp.address=:26900
  - --entryPoints.seven-days-to-die-udp-main.address=:26900/udp
  - --entryPoints.seven-days-to-die-udp-plus-1.address=:26901/udp
  - --entryPoints.seven-days-to-die-udp-plus-2.address=:26902/udp
```

Traefikコンテナの`ports`へ追加します。

```yaml
ports:
  - "0.0.0.0:26900:26900/tcp"
  - "0.0.0.0:26900:26900/udp"
  - "0.0.0.0:26901:26901/udp"
  - "0.0.0.0:26902:26902/udp"
```

7D2Dコンテナは`onprem-relay-ingress`ネットワークへ接続し、`seven-days-to-die`というネットワークエイリアスを付けます。Traefikがホストポートを所有するため、7D2Dコンテナ自身の`ports`公開は不要です。

```yaml
services:
  seven-days-to-die:
    networks:
      relay-ingress:
        aliases:
          - seven-days-to-die

networks:
  relay-ingress:
    external: true
    name: onprem-relay-ingress
```

Terraform:

```hcl
public_tcp_ports = [25565, 26900]
public_udp_ports = [26900, 26901, 26902]
```

OCI転送:

```bash
./scripts/wg-relay.sh forward add 7d2d-tcp --protocol tcp --listen-port 26900 --target-address 10.99.0.2 --target-port 26900
./scripts/wg-relay.sh forward add 7d2d-udp-main --protocol udp --listen-port 26900 --target-address 10.99.0.2 --target-port 26900
./scripts/wg-relay.sh forward add 7d2d-udp-plus-1 --protocol udp --listen-port 26901 --target-address 10.99.0.2 --target-port 26901
./scripts/wg-relay.sh forward add 7d2d-udp-plus-2 --protocol udp --listen-port 26902 --target-address 10.99.0.2 --target-port 26902
```

同じ番号のTCPとUDPは別ルールとして共存できます。

## 転送ルールの更新と削除

転送先ポートなどを変更するとき:

```bash
./scripts/wg-relay.sh forward update minecraft \
  --protocol tcp \
  --listen-port 25565 \
  --target-address 10.99.0.2 \
  --target-port 25565
```

削除:

```bash
./scripts/wg-relay.sh forward delete minecraft
```

OCIの転送を削除してもNSGは自動変更されません。不要になった公開ポートは`terraform.tfvars`からも削除し、Terraformを再適用してください。

## 運用上の注意

- 一般的なTCP/UDPはドメイン名ではなくポートで振り分けます。
- 同じゲームを同じ公開ポートで複数起動できるのは、mc-routerのようなプロトコル対応ルーターがある場合だけです。
- Docker管理画面、RCON、Telnet、管理APIは一般公開しないでください。
- Traefikとmc-routerは入口の単一障害点になるため、`restart: unless-stopped`を設定しています。
- OCIのSNATにより実クライアントIPはゲームコンテナへ渡りません。
