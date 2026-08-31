# 変更履歴

## Unreleased

- WireGuardトンネルへ`fdae:3e62:c345:99::/64`のULA IPv6を追加し、既存IPv4・Peer鍵を
  維持したまま段階移行できるようにした。新規設定のIPv6自動割当て、Dashboard表示、
  Peer間アクセスプリセットのIPv6フィルタ同期にも対応。
- WireGuardクライアントの公開EndpointをIPv6主系に変更し、IPv6出力を取得できない場合だけ
  既存の予約済みIPv4 Endpointへ退避するようにした。稼働中Peerを再起動せず、今後発行する
  設定のEndpointだけを切り替える管理コマンドも追加。トンネル内IPv4と既存Peer鍵は維持する。
- WireGuardのMTUを1380へ固定し、VPSからトンネルへ転送するTCPのMSSを経路MTUへ
  クランプすることで、IPv4 PPPoE回線で大きいTLS・HTTP応答だけが停止する問題を修正。
- OCI NSGへIPv4・IPv6のPath MTU Discoveryに必要なICMPルールを追加。
- 新しく発行するWireGuard Peer設定へMTU 1380を含め、既存Peerの移行手順を追加。
