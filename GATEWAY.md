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
  ├─ TCP/80（IP直アクセス）→ Traefik → VPN管理ハブ
  ├─ TCP/80・443（公開FQDN）→ Traefik → Webコンテナ
  └─ ゲーム固有ポート → 各ゲームコンテナ
```

WebはTraefikがHTTPSのHTTP Host名で振り分け、TCP/80へのアクセスは443へ転送します。
証明書はLet's Encrypt HTTP-01で自動取得します。Minecraftを含むTCP/UDPゲームは、
ゲームコンテナがWindowsホストへ公開したポートへOCIから直接転送します。
クライアントは接続先ポートを指定するため、ゲーム用のTraefik EntryPointやmc-routerは
使用しません。

## 初期構成

リポジトリの`gateway`ディレクトリには次の入口を用意しています。

- TCP/80: Let's Encrypt HTTP-01とHTTPSリダイレクト
- TCP/443: HTTPS Web用Traefik EntryPoint

WireGuard内から`http://10.99.0.2`へIPアドレスでアクセスした場合だけ、TCP/80は
VPN管理ハブへ振り分けます。公開FQDNへのHTTPアクセスは従来どおりHTTPSへ転送します。

ゲーム用ポートは`gateway/compose.yaml`で公開しません。各ゲームコンテナの`ports`と、
OCI NSG・`wg-relay forward`で管理します。

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

ゲームコンテナが必要なTCP/UDPポートをWindowsホストへ公開していることを確認します。

```powershell
docker ps --format "table {{.Names}}\t{{.Ports}}"
```

## 2. Windowsで入口コンテナを起動する

リポジトリのルートで実行します。

```powershell
docker compose --env-file gateway/.env -f gateway/compose.yaml config
docker compose --env-file gateway/.env -f gateway/compose.yaml pull
docker compose --env-file gateway/.env -f gateway/compose.yaml up -d --remove-orphans
docker compose --env-file gateway/.env -f gateway/compose.yaml ps
```

`--remove-orphans`は、以前の構成で起動したmc-routerなど、現在のComposeに存在しない
コンテナを停止して削除します。Traefikの証明書Volumeは削除しません。

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

## VPN管理ハブを開く

WireGuardへ接続した管理端末で次を開きます。ハブ自身はHTTPですが、通信経路は
WireGuardで暗号化されます。

```text
http://10.99.0.2
```

管理端末のWireGuard Peerには、MiniPCの`10.99.0.2`に対するTCP/80のPeer間アクセス許可が
必要です。OCI Relay ControlのWireGuard画面で対象Peerの「アクセス追加」を開き、接続先を
`10.99.0.2`、プロトコルをTCP、ポートを`80`として追加します。現在の`mac-admin`
（`10.99.0.3`）には`mac-to-admin-hub`として設定済みです。

初期状態では次の管理画面をカードから開けます。

| 管理画面 | 接続先 |
| --- | --- |
| OCI Relay Control | `http://10.99.0.2:8081` |
| Docker Dashboard | `https://10.99.0.2:8082` |

Docker Dashboardはプライベート管理入口用の自己署名証明書を使用するため、証明書をまだ
信頼していない端末では初回に警告が表示されます。ハブは認証情報やアクセストークンを
保存せず、それぞれの管理画面が持つ既存の認証をそのまま利用します。

管理ハブは`C:\Develop\admin-hub`の独立プロジェクトとして稼働します。Gatewayを先に起動して
`onprem-relay-ingress`ネットワークを作成してから、管理ハブを起動します。

```powershell
Set-Location C:\Develop\admin-hub
docker compose config --quiet
docker compose build
docker compose up -d
```

カードを追加・変更するときは`C:\Develop\admin-hub\static\services.json`を編集し、同じ
ディレクトリで`docker compose build`と`docker compose up -d`を実行します。
`id`、`name`、`description`、`url`、`accessLabel`をすべて指定します。ハブはホストへ
独自ポートを公開せず、Traefikと同じ`onprem-relay-ingress`ネットワークからだけ配信します。
Docker socket、管理API資格情報、各サービスの秘密情報は渡しません。

## WebサービスをRelay Controlから登録する

Relay Controlの「Webサービス」で次の順に操作します。

1. 「Web入口を準備」でTCP/80・443のOCI経路を下書きする
2. 公開経路の「変更を確認」でTerraform planを確認し、`APPLY`で反映する
3. WebルートへFQDN、Dockerネットワークエイリアス、コンテナポートを保存する
4. 「反映内容を確認」で生成設定を確認し、`PUBLISH`でTraefikへ反映する
5. MyDNSのAレコードをOCIの予約済みIPv4へ向ける

Webルートの保存だけではTraefikを変更しません。Relay Controlが更新するのは
`gateway/traefik/dynamic/ui-web-routes.yml`だけです。

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
docker compose --env-file gateway/.env -f gateway/compose.yaml logs --tail 100 traefik
```

## Minecraftへポート指定で直接接続する

複数のMinecraftサーバーを公開する場合は、それぞれ異なるWindowsホストポートを割り当てます。
例えば、通常サーバーをTCP/41409、ハードコアサーバーをTCP/41411で公開します。
mc-routerやホスト名マッピングは使用しません。

Windows Defender Firewallで確認を求められた場合は、パブリックネットワーク全体ではなく、WireGuard経由で必要な受信だけを許可してください。

## 3. TerraformでOCIの公開ポートを許可する

Mac側の`terraform.tfvars`へゲームコンテナが公開しているTCPポートを追加します。
次はWeb入口と2つのMinecraftサーバーを公開する例です。

```hcl
public_tcp_ports = [80, 443, 41409, 41411]
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
./scripts/wg-relay.sh forward add minecraft --protocol tcp --listen-port 41409 --target-address 10.99.0.2 --target-port 41409
./scripts/wg-relay.sh forward add minecraft-hardcore --protocol tcp --listen-port 41411 --target-address 10.99.0.2 --target-port 41411
```

このルールはTraefikを経由せず、次の変換を行います。

```text
OCI TCP/41409 → WireGuard → Windows TCP/41409 → Minecraftコンテナ
OCI TCP/41411 → WireGuard → Windows TCP/41411 → Minecraftコンテナ
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
minecraft.example.mydns.jp:41409
minecraft-hardcore.example.mydns.jp:41411
```

## 一般的なTCP/UDPゲームを追加する

新しいゲームは次の3層へ同じ公開ポートを追加します。

1. ゲームコンテナのWindowsホスト公開ポート
2. Terraformの`public_tcp_ports`または`public_udp_ports`
3. OCIの`wg-relay forward`

### 7 Days to Dieの例

7D2Dコンテナ自身の`ports`で必要なポートをWindowsホストへ公開します。

```yaml
ports:
  - "0.0.0.0:26900:26900/tcp"
  - "0.0.0.0:26900:26900/udp"
  - "0.0.0.0:26901:26901/udp"
  - "0.0.0.0:26902:26902/udp"
```

Terraform:

```hcl
public_tcp_ports = [41409, 41411, 26900]
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
./scripts/wg-relay.sh forward update minecraft --protocol tcp --listen-port 41409 --target-address 10.99.0.2 --target-port 41409
```

削除:

```bash
./scripts/wg-relay.sh forward delete minecraft
```

OCIの転送を削除してもNSGは自動変更されません。不要になった公開ポートは`terraform.tfvars`からも削除し、Terraformを再適用してください。

## 運用上の注意

- 一般的なTCP/UDPはドメイン名ではなくポートで振り分けます。
- 複数のゲームサーバーは、それぞれ異なる公開ポートへ割り当てます。
- Docker管理画面、RCON、Telnet、管理APIは一般公開しないでください。
- TraefikはWeb入口だけを担当し、ゲーム通信は経由しません。
- OCIのSNATにより実クライアントIPはゲームコンテナへ渡りません。
