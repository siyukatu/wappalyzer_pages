# Wappalyzer Pages 改善サイクル実行マニュアル

> **この文書は、次回以降の作業者・AIエージェントに対する実行指示書です。**
> 対象リポジトリ: https://github.com/siyukatu/wappalyzer_pages
> 実サイト: https://wappalyzer-technologies.pages.dev/
> 状態記録: [improvement-cycle-state.json](./improvement-cycle-state.json)
>
> 再開指示の例: **「https://github.com/siyukatu/wappalyzer_pages/blob/main/docs/improvement-cycle-manual.md を読み、指示に従ってください」**

## 0. 目的と最優先の制約

**目的:** Chrome Web Store配布の本物の Wappalyzer 拡張機能が、実サイトのトップレベルタブで返す *重複除去済み技術名の数* を、実測で増やす。単に生成した候補数や近似検出器のスコアを増やすことは目的ではない。

**絶対条件:**

1. Cloudflare Pages の **静的アセットと `_headers` のみ**で完結する。**Cloudflare Pages Functions、`functions/`、`_worker.js`、Workers、動的バックエンドを追加しない。**
2. 本番サイトから外部オリジンへの実際の通信を増やさない。既存の厳格な CSP を保つ（`connect-src 'none'`、外部スクリプト・画像・CSS の実行／取得は禁止）。iframe を使う場合は同一オリジン限定。既存の CSP ハッシュ、XSS 保護、ブラウザーの安全性を壊さない。
3. **公式 CRX のネイティブ検出結果**だけを採否基準とする。直接エンジンを呼ぶ補助解析の約 6,990 件、生成ルール数、CSV の過去の値はネイティブ検出数と混同しない。
4. **検出の回帰を原則として採用しない。** 単純な合計数だけでなく `gained` と `lost` の技術名を確認する。同じ CRX バージョン・ルール SHA、同じブラウザー条件で比較する。例外はユーザーの明示的な許可がある場合のみ。
5. 本番へ変更する前にリポジトリと Actions の最新状態を確認する。他者の変更を上書きしない。作業者が GitHub の編集権限を持たない場合は、未実施と明記してパッチを提示する。実行していない検査を「成功」と書かない。
6. ページは**合成フィンガープリント**であり、検出技術が本当にインストールされているという意味ではない。

## 1. 初回の読み取り（毎回必須）

- `README.md`、このマニュアル、`docs/improvement-cycle-state.json`、`docs/detection-gap-analysis.md` を読む。
- `scripts/build.mjs`、`scripts/enrich.mjs`、`scripts/header-optimizer.mjs`、`scripts/header-shards.mjs`、`scripts/verify-generated.mjs`、`scripts/selfcheck-native.mjs`、`scripts/selenium-capture.py`、`.github/workflows/build.yml`、`.github/workflows/selfcheck.yml` を確認する。
- GitHub の `main` 最新 SHA、成功した build / selfcheck の Actions 実行 ID、アーティファクト `selenium-selfcheck/report.json` の `nativeExtension.detected`、`nativeExtension.technologies`、`nativeExtension.trend`、`ruleSource.version`、`ruleSource.sha256` を取得する。
- 同一の公式 CRX バージョンとルール SHA が揃っているか確認する。異なる場合は数の単純比較を禁止し、新しいベースラインとして扱う。
- 最新のデプロイ SHA と検査対象 SHA が一致するか確認する。未デプロイなら待機／再試行するが、無期限に待たない。
- 作業開始時の値を状態記録に書く。直近の検証済みベースラインは **Wappalyzer 6.12.8、7,341 定義、ネイティブ 4,224、未検出 3,117**（2026-10-30 UTC の成功実測）。これは**固定目標値ではなく、再測定すべき履歴値**。

## 2. 1回の改善イテレーション

1. **仮説:** 最新の未検出技術名と、公式 CRX 定義の `headers`、`dom`、`js`、`meta`、`cookies`、`html`、`scriptSrc` などのチャネルを照合する。既知の不成功案を無検証で繰り返さない。候補の期待利得、リスク、検証方法を記録する。
2. **小さな変更:** 1回に1つの独立した仮説を試す。変更前の `main` SHA と対象ファイルを保存し、戻せるようにする。生成結果だけでなく、ブラウザー実行時にどのチャネルで検出されるかを検討する。
3. **ローカル／CI検証:** Node.js 22 で `npm run build`、`node scripts/verify-generated.mjs` を実行する。GitHub Actions の build ワークフローの成功も確認する。すべての HTML が1行、CSPハッシュ一致、25 MiB/ファイル以内、`_headers` が100パスルール以内・各行2,000文字以内であることを確認する。これらの Cloudflare 制約は「HTTPレスポンスのヘッダー数上限」とは別。
4. **Push と本番反映:** 権限がある場合のみ変更を commit / push する。Cloudflare Pages の `wappalyzer-pages-commit` と `build-info.json.sourceCommit` が対象 SHA になったことを確認する。
5. **ネイティブ実測:** `.github/workflows/selfcheck.yml` の実行結果（build成功後の自動起動、または手動起動）を待つ。GitHub Actions の `selenium-selfcheck` アーティファクトを取得する。拡張機能のバックグラウンドドライバーが返す `nativeExtension.detected` と `technologies` を採用する。デプロイ不一致、CRX取得失敗、ブラウザー検査失敗、アーティファクト欠損は「改善なし」ではなく「未検証」。
6. **差分判定:** 前後のネイティブ技術名を正規化（NFKC・trim・小文字化）して比較し、`gained`、`lost`、総数、CRXバージョンとルール SHA、GitHub commit / Actions run URL を記録する。
7. **採用・撤回:** 同条件で純増し、かつ既存技術の損失がなければ採用する。総数が同じでも新規と損失が混在すれば自動採用しない。減少・安全性違反・テスト失敗なら原因を調査して修正または revert し、再計測する。効果ゼロの変更は、検証基盤の改善等の明確な理由がなければ撤回または非本番の実験に移す。
8. **記録して次へ:** `docs/improvement-cycle-state.json` を更新し、仮説・結果・技術名差分・失敗理由・次候補を記録して commit する。成功した場合は次の独立仮説に進む。失敗した場合も学習内容を残し、同じ失敗を反復しない。

## 3. 既知の実測と再試行を避ける事項

- 2026-10-30 UTC の iframe ヘッダー分割実験では、`/header-shards/01`、`/02`、`/03` がすべて HTTP 200 で読み込まれたが、ネイティブ検出は **4,224 → 4,224（新規0、損失0）**。実測: https://github.com/siyukatu/wappalyzer_pages/actions/runs/41084074060
- **iframe内レスポンスヘッダーが親タブの検出に集約されるとは仮定しない。** iframeにヘッダーを増やすだけの再実装は優先しない。
- Cloudflare Pages は `.html` の URL を拡張子なしに正規化することがある。iframe URL と `_headers` のパスルールを実配信 URL に合わせる。
- `_headers` の100という制限は**パスルール数**であり、レスポンスヘッダーフィールド数ではない。ブラウザー・HTTPパーサー・CDNの個数／サイズ制限は独立に検証する。
- 過去の手動CSV 2,841 / 3,161 / 3,361 と、補助解析 6,990 は、公式CRXのネイティブ 4,224 と同列比較しない。

## 4. 次の候補（最新の実測で優先順位を更新）

1. **親ページのレスポンスヘッダーの値最適化。** 特に `X-Powered-By`、`Via` のアンカー付き正規表現と既存検出名の保護を検証する。現在の root header を無闇に置換しない。
2. **未検出DOM/JSルールのブラウザー実行時解析。** ルール生成時の正規表現マッチと拡張機能の実際の収集経路を突き合わせ、真の未到達原因を探す。
3. **Cookie制限・DOMプロパティ・正規表現 witness の個別最適化。** 既存 180 通常 + 145 partitioned cookie 等の成功条件を壊さずに検証する。
4. **新しいCRXへの追従。** 最新定義で未検出技術の構成が変われば、新しいベースラインを作って優先順位を更新する。

## 5. 継続と停止条件

**会話1ターンで無限の実行を保証することはできない。** 作業環境の時間、権限、GitHub Actionsの制限、Cloudflareデプロイ待ちがある。各起動では実行可能な範囲で複数イテレーションを試し、途中で終了しても状態ファイルから次回再開できるようにする。自動化・スケジュールが有効な場合も実行結果と権限を毎回確認する。

- 連続3件以上の**互いに独立した**高優先度の仮説で純増がなく、残りの候補に具体的な検出経路・実現可能性がない場合は、変更を伴う探索を一旦停止して「現時点で改善余地が見込めない」と記録する。**数学的な最適値の証明ではない。**
- 新しいCRX、未検出ルール、ブラウザー仕様、Cloudflare Pages仕様、または有力な仮説が出た場合は探索を再開する。定期チェックは続けてもよいが、検出が変わらないだけで無意味なcommitやActions実行を増やさない。
- 外部サービスの障害、GitHub Actions使用量、認証・書き込み権限、リポジトリ保護等により進められない場合は停止して報告する。無限ループ、無制限の自己Push、無制限の課金はしない。
- 毎回の報告に「前後のネイティブ件数、追加・消失技術名、CRXバージョン、変更ファイル、コミットとActionsリンク、未実施の工程、次の候補」を含める。

## 6. AIエージェントへの再開指示（このURLだけで実行）

この文書をユーザーから指定されたら、**調査レポートの作成だけで終了しないこと**。GitHubへのアクセス・書き込み権限を確認し、状態ファイルを読み、実際にコードを編集・commit・Push・GitHub Actionsで検証・本番のネイティブ検出数を比較し、回帰を撤回して次の仮説を試す。進められる限りイテレーションを繰り返す。許可のない危険な操作、Cloudflare Pages Functions、外部ランタイム通信は行わない。実行不能なら理由と次の具体的な手順を記録する。終了時には状態ファイルを更新して再開可能にする。

