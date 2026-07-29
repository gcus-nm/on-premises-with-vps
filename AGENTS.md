# プロジェクト運用指示

- ユーザー向けドキュメントと作業報告は日本語で記述する。
- Terraform変更後は`terraform fmt -check`と`terraform validate`を実行する。
- 稼働中インスタンスを置換するplanは、理由と影響を確認してから適用する。
- OCI Always Freeの範囲を優先し、課金につながる可能性がある変更はplanと公式仕様を確認する。
- WireGuard秘密鍵、SSH秘密鍵、OCI API秘密鍵、実値入り`terraform.tfvars`をGitへ追加しない。
- 既存のOCI Object Storageバックエンドと予約済みパブリックIPv4アドレスを維持する。
