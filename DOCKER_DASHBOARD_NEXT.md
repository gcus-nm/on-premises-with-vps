# Docker Dashboard Next Relay

`dashboard.oci.gcusnm.mydns.jp` はRelay Controlの生成ファイルと分離した固定経路です。旧版の `docker-dashboard.oci.gcusnm.mydns.jp` は変更しません。`gateway/traefik/dynamic/docker-dashboard-next.yml` から `onprem-relay-ingress` 上の `docker-dashboard-next:8081` へ転送します。

## DNSと証明書

MyDNSでは次の通常Aレコードだけを追加します。ワイルドカード、子IDへのDELEGATE、DNS-01資格情報は不要です。

```text
dashboard.oci.gcusnm.mydns.jp A 161.33.162.42
```

証明書は既存サービスと同じHTTP-01 resolver `letsencrypt` が取得します。既存の `.env` でstaging resolverを使用している場合は、staging発行を確認してから通常のproduction endpointへ戻します。

```powershell
docker compose --env-file gateway/.env -f gateway/compose.yaml config --quiet
docker compose --env-file gateway/.env -f gateway/compose.yaml up -d --force-recreate traefik
docker compose --env-file gateway/.env -f gateway/compose.yaml logs --tail 100 traefik
```

## アクセスリンク

管理画面が発行するURLは `https://dashboard.oci.gcusnm.mydns.jp/access/<token>` です。初回アクセス時にトークンをHttpOnly Cookieセッションへ交換し、ブラウザのURLを `/` へ戻します。完全URLやトークンをログ・ドキュメントへ記録しません。
