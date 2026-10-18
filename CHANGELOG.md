# 変更履歴

## Unreleased

- HTTP接続などで`crypto.randomUUID()`が提供されないブラウザーでも、アクセスグループ・
  Peer割り当てを保存できるよう、冪等性キー生成を`crypto.getRandomValues()`へ変更。

- アクセスプリセットをネスト・共有できるアクセスグループを追加。Peerへの直接指定との合算、
  複数ポートの同時登録、許可経路表示、保存前の全Peer差分確認、競合検出に対応。
  OCI側に正本を保存し、既存割り当ての移行、失敗時・未完了処理の復元を追加。
  参照中プリセットの削除は、従来の割り当てごとの削除から拒否へ変更。
  新API・CLIを追加。利用前にOCIリレー管理スクリプトの更新が必要（配備・実通信確認は別途）。

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
