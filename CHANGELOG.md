# 変更履歴

## Unreleased

- WireGuardのMTUを1380へ固定し、VPSからトンネルへ転送するTCPのMSSを経路MTUへ
  クランプすることで、IPv4 PPPoE回線で大きいTLS・HTTP応答だけが停止する問題を修正。
- OCI NSGへIPv4・IPv6のPath MTU Discoveryに必要なICMPルールを追加。
- 新しく発行するWireGuard Peer設定へMTU 1380を含め、既存Peerの移行手順を追加。
