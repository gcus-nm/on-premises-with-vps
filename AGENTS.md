# プロジェクト運用指示

- ユーザー向けドキュメントと作業報告は日本語で記述する。
- Terraform変更後は`terraform fmt -check`と`terraform validate`を実行する。
- 稼働中インスタンスを置換するplanは、理由と影響を確認してから適用する。
- OCI Always Freeの範囲を優先し、課金につながる可能性がある変更はplanと公式仕様を確認する。
- WireGuard秘密鍵、SSH秘密鍵、OCI API秘密鍵、実値入り`terraform.tfvars`をGitへ追加しない。
- 既存のOCI Object Storageバックエンドと予約済みパブリックIPv4アドレスを維持する。
- Relay Dashboard CLIはHTTP Basic認証情報を環境変数からだけ取得し、同じAPIと業務検証を利用する。
- 実変更CLIは接続先Originの確認と冪等性キーを必須とし、APIのdry-run・監査・部分失敗情報を維持する。
