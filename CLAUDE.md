# KODIS

Key-scoped Operations & Deterministic Inspection System。
模擬Microsoft Entra環境に対して Inspect → Evaluate → Plan → Approve → Execute → Verify を行う防御エージェント（OSS志向）。

## 絶対ルール
- 実顧客データ・実テナント・実Graph APIに接続するコードを書かない。ネットワークは httptest のループバックのみ使う。
- フィクスチャは合成データのみ。実在のドメイン・UPN・テナントIDを使わない（`example.test` を使う）。
- 依存を追加しない。go.mod に `require` を追加する変更は、事前にユーザーの承認を得る。
- npm/node 関連ファイルをリポジトリに追加しない。
- git push、force push、履歴の改変をしない。コミットはユーザーの指示があるときだけ行う。

## MVPスコープ
- LLMは使わない。Plan は決定的なルールで生成する。将来LLMを入れる場合も、Plan は未信頼JSONとして同じ検証経路を通す。
- 許可する操作は1つだけ: Conditional Access ポリシーの state を `disabled` から `enabledForReportingButNotEnforced` に変える。

## 安全不変条件（変更するときは該当テストを追加する）
1. 既定は拒否（fail closed）。不明な操作・欠けたフィールド・未知のフィールド・パース失敗・期限切れは、すべて拒否する。
2. Plan は未信頼入力として扱う。policy が許可していない Action は存在しないものとして扱う。
3. Executor は policy の判定を信頼せず、次を自分で再検証する:
   承認署名 / Planハッシュの一致 / 有効期限 / 内蔵の許可リスト / 書き込み直前の事前条件（versionが一致するときだけ書き込むCAS）。
4. 承認は特定の Plan ハッシュに束縛する。Plan が1バイトでも変われば無効にする。
5. Verify は Executor の戻り値を使わず、別の Reader で状態を取り直して比較する。
6. 拒否を含むすべての判定を audit に記録する。
7. 監査ログは `audit-init` で明示的に作る。実行時には外部に保管したチェックポイントを必須とし、一致しなければ止める。ログの初期化・復旧より前に発行された承認は実行しない。限界は docs/audit-checkpoint.md に書いたとおりで、それ以上を保証すると主張しない。

## パッケージ境界
- `entra.Writer` を参照してよいのは `internal/execute` と `internal/mockentra` だけ。
- `internal/mockentra` を import してよいのは `cmd/kodis` だけ（テストを除く）。mock は `entra.Writer` を経由せずに書き込めるため。
- `internal/policy` は I/O を持たない（os, net, net/http, os/exec, io/fs, syscall を import しない）。
- モジュール内のどのパッケージも、`reflect`・`unsafe`・`text/template`・`html/template`・`net/rpc`・`plugin`（サブパッケージを含む）を import しない。メソッドを文字列の名前で呼べるため、静的な境界の検査をすり抜ける。
- 境界は `internal/archtest` が強制する。ルールを緩める変更は、ユーザーの明示的な承認なしに行わない。

## 開発コマンド
環境変数 `GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly` を前提にする（.claude/settings.json で設定済み）。
- フォーマット: `gofmt -l .`（出力が空であること）
- 静的検査: `scripts/safe-test.sh go vet ./...`
- テスト: `scripts/safe-test.sh go test -race -count=1 ./...`
- 変更したら上記3つがすべて通ることを確認してから完了と報告する。失敗した場合は出力をそのまま報告する。

## テストの安全性
- `go test` / `go vet` / 変異テスト / テスト用バイナリの実行は、必ず `scripts/safe-test.sh` 経由で行う。systemd user scope で MemoryMax=2G・MemorySwapMax=0・CPUQuota=200%・TasksMax=512・timeout 300秒 を課す。環境変数（KODIS_MEM_MAX など）で下げることはできるが、上げる・外す値（上限超え、0、infinity、空など）は実行前に拒否される。scope を作れない場合も何も実行しない。
- 変異テストでは上限を下げる（例: `KODIS_MEM_MAX=1G KODIS_TIMEOUT=120`）。
- テストに上限のない入力（`/dev/zero`、無限に返す Reader など）を使わない。入力側に上限を持たせ、検査対象の上限処理が壊れてもテストが有限量で失敗するようにする。
- 経緯: 2026-10-25、上限処理を外した変異テストが `/dev/zero` を読み続け、ホストのメモリを枯渇させて端末が OOM kill された。

## コーディング
- Go標準ライブラリのみ使う。エラーは握りつぶさない。panic を使わない。
- 拒否理由は、理由コードを持つ型付きエラーで返す。
- JSON の読み込みには `DisallowUnknownFields` を使う。
- 時刻と乱数は外から注入し、テストを決定的にする。
- テストは、拒否系のケースを許可系より多く書く。

## レビュー
- 独立レビューは Codex に読み取り専用で依頼する。渡すのは差分・脅威モデル・この安全不変条件だけで、Claude の結論は渡さない。
- 指摘は、失敗するテストで再現してから修正する。同意しない指摘は理由を残し、ユーザーに判断を委ねる。
