# Wappalyzer fingerprint Pages

Synthetic fingerprint benchmark: downloads the **latest public Wappalyzer CRX from the Chrome Web Store** and extracts every bundled `technologies/*.json` file **at build time**, then generates static HTML documents containing as many passive detection signatures as practical.

> **Warning:** This is a deliberately misleading fingerprint benchmark, **not** evidence that a listed technology is installed. It will not trigger every Wappalyzer rule: HTTP headers, DNS, cookies, TLS, live network traffic, and difficult regular expressions cannot all be represented faithfully in one HTML file. Actual detector output depends on Wappalyzer version and browser CSP handling.

## Non-negotiable hosting constraints

**Cloudflare Pages static assets only. Cloudflare Pages Functions are strictly prohibited.** Do not add a `functions/` directory, `_worker.js`, a Worker, server-side middleware, a dynamic backend, or any runtime service dependency. Generation and Selenium verification run in GitHub Actions or during the Pages build; the deployed site consists exclusively of static files and `_headers`. No third-party network requests are permitted at runtime.

## Cloudflare Pages

- Connect this repository using **Workers & Pages → Create → Pages → Connect to Git**.
- Production branch: `main`
- Framework preset: **None**
- Build command: `npm run build`
- Build output directory: `dist`
- Node.js version: 20 or later

Every Cloudflare Pages build downloads the official Chrome Web Store CRX for Wappalyzer extension `gppongmhjkpfnbhagpmjfkannfbllamg` through Google's Chrome extension update endpoint, decodes CRX3, and extracts **all 27 bundled `technologies/*.json`** files. On the first verified test, CRX **6.12.8** contained **7,341** technology definitions, compared with **4,005** in the previous public GitHub snapshot. The actual version, SHA-256 and counts are included in `dist/build-info.json` under `ruleSource`. A missing/invalid CRX **fails the build**; the generator never silently falls back to old public JSON definitions. No rules or proprietary extension files are committed or published to Pages. For automatic upstream refresh, configure a Cloudflare Pages deploy hook and call it on a schedule.

The generated `dist/index.html` remains the top-level synthetic fingerprint page. Cloudflare Pages applies `dist/_headers`, whose CSP denies all outbound network requests (`default-src 'none'`, `connect-src 'none'`, etc.) and permits only a hash-verified inline script for synthetic JavaScript globals. Script and stylesheet URLs in the document are intentionally non-functional: CSP blocks them. Static header-shard iframes were retired after proving zero native detection gain. The generated page retains synthetic iframe *DOM attributes* for rule matching but blocks **all frame navigations** via `frame-src 'none'` and `child-src 'none'`. There are no `dist/header-shards/` assets or shard-specific `_headers` rules.

Run locally: `npm run build` then serve `dist` using a static file server (local file access will not apply the `_headers` CSP).

The source GitHub repository can remain private even though a production Pages site is publicly reachable. Deploying to Pages is a separate Cloudflare account action.

## Static-only detection expansion

- `scripts/enrich.mjs` scans **every** technology definition for header, DOM, JavaScript and cookie rules, in addition to the existing HTML/meta/script URL rules. It creates best-effort matching witnesses, not full regex solutions.
- `dist/_headers` dynamically contains synthetic, noncritical HTTP response headers inferred from Wappalyzer's `headers` field, along with restrictive CSP and security headers. Header names which could compromise HTTP semantics or Cloudflare's operation are intentionally excluded. Generated values are budgeted for reasonable response sizes.
- `dist/404.html` is a real static 404 page, so Pages does not silently serve the homepage for missing paths.
- `dist/robots.txt` opts out of crawler indexing. `dist/build-info.json` records signature counts.
- A narrowly scoped inline script creates synthetic JavaScript globals and a capped set of first-party, non-sensitive cookies. No external requests, third-party scripts, or Cloudflare Functions are involved. Cookie creation has browser storage side effects; disable cookies in your test browser profile if unwanted.
- The CSP deliberately prevents all external resources, including synthetic `script src` and `link` URLs. Such URLs may remain detectable as DOM attributes, but will not be loaded.
- The generated custom HTTP header values are intentionally **false positives** and may not resemble real production software. They should not be used for fingerprint evasion, compliance, or security posture claims.

Cloudflare documents a limit of **100 `_headers` path rules** and **2,000 characters per header line**; this is **not** a limit of 100 HTTP response header fields. The generator uses a wildcard security-header rule and exact `/` and `/index.html` fingerprint rules (three path rules in total). Each line stays within 2,000 characters. There are no iframe header shards or shard-specific HTTP requests. The original root header values are retained, with no Cloudflare Pages Functions. Cloudflare Pages currently limits static file size to 25 MiB. The build must never create `functions/` or `_worker.js`. **Wappalyzer may ignore iframe response headers**; only the real-extension Selenium result establishes whether this improves detection.

Documentation: https://developers.cloudflare.com/pages/configuration/headers/ and https://developers.cloudflare.com/pages/configuration/serving-pages/

## Invisible fingerprint page

The generated index uses a SHA-256-authorized inline `<style id="wappalyzer-conceal">` that moves the body offscreen, clips it, and makes it transparent while **preserving text exposure to DOM readers**. It blocks iframe/object/embed rendering; synthetic iframe `src` witnesses remain queryable but cannot initiate an HTTP navigation because `frame-src 'none'` and `child-src 'none'` are enforced. The fingerprint container intentionally does not use the `hidden` attribute, since the extension filters it out even when CSS overrides `display`. The offscreen/transparent body keeps the page visually empty. The CSP `style-src` permits **only the SHA-256 hash** of this exact generated style, without `unsafe-inline`. A fixed nonce would not provide meaningful request-specific security on a static Cloudflare Pages deployment. JavaScript remains governed by a separate hashed `script-src` directive. No Functions are needed.

## Compact global fingerprint synthesis

`scripts/globals.mjs` generates **one prefix-sharing property tree** from all `js` technology rules instead of repeating JavaScript assignments or maintaining two independent lists. Candidate values are verified against the source rule's regular expression; unsupported patterns fall back to an object placeholder. Unsafe global names and prototype-sensitive keys are skipped. Nested paths preserve their parent object shape, and the one-page CSP script hash is recalculated at each build.

`dist/build-info.json` reports `globals.globalPaths`, `globals.globalPatternMatches`, `globals.globalTreeBytes` and `globals.globalScriptBytes`. These are generation metrics, not confirmed Wappalyzer detections.

## Compare against the user-exported detection baseline

The original Wappalyzer CSV export was normalized into `data/detected-baseline.json` (2,841 unique technology names). The second Wappalyzer export contains **3,161** distinct names: **458 new detections** and **138 lost** relative to the first scan. Differences are stored in `data/detection-gains.json` and `data/detection-regressions.json`. Each build emits `dist/coverage.json` against the **second** scan and `dist/coverage-original.json` against the first; it prioritizes absent and regressed signatures.

Re-export the live site from Wappalyzer after Cloudflare Pages redeploys, then run:

```sh
node scripts/compare.mjs ./new-wappalyzer-export.csv
```

This displays **newly detected** and **no-longer detected** names, their totals, and net change **relative to the second scan** (add `--original` to compare against the first scan). A successful build only verifies generated signatures and CSP hashes, **not actual Wappalyzer detection** at the live URL.

The updated regex witness generator (`scripts/regex-witness.mjs`) correctly handles optional groups and character classes in substantially more rules. Empty meta/header rules are treated as presence checks. The generator adds inert inline-script signatures, stronger DOM attribute witnesses, plus up to two validated `scriptSrc` candidates for previously regressed technologies (including deliberately invalid hostnames that still match Wappalyzer's regex). The `_headers` generation prioritizes technologies absent from the second CSV.

See [Detection gap analysis](docs/detection-gap-analysis.md) for measurements, examples, and limitations.

## Single-line compressed HTML and runtime guarantees

- Both `dist/index.html` and `dist/404.html` contain **zero CR/LF bytes**. Markup, HTML-regex comments, attributes and JS witnesses are deliberately retained; no destructive HTML minifier is used.
- The prefix-sharing JavaScript tree uses scalar leaves instead of repeated empty objects. Synthetic global variables are still generated by one inline script, authorized by its CSP SHA-256 hash.
- Simple descendant/child DOM selector chains, rule-specific DOM text, Open Graph `property` metadata and 33 currently matchable CSS-rule snippets are synthesized at build time.
- Up to **170** Secure/SameSite first-party cookies are attempted, prioritized toward previously missing technologies; this can change browser cookie state.
- External script/stylesheet URLs are **intentionally not fetched**. If a malformed URL is a useful Wappalyzer signature it is retained; outbound requests remain forbidden by CSP.
- GitHub Actions verifies single-line markup, CSP hashes, page limits, and executes the synthetic bootstrap in a restricted Node VM to catch runtime errors. True Wappalyzer detections still require re-exporting the live page after Cloudflare deploys.

The [second-scan assessment](docs/second-scan.md) describes the measured 458 gained / 138 lost and known remaining limitations.

## Chrome Web Store CRX rule source (current)

- **Primary and required:** Chrome Web Store [Wappalyzer - Technology profiler](https://chromewebstore.google.com/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg), extension ID `gppongmhjkpfnbhagpmjfkannfbllamg`.
- **Downloader and extractor:** `scripts/store-rules.mjs`. It uses Google's official `clients2.google.com/service/update2/crx` endpoint, verifies the CRX/ZIP structure and size limits, reads the extension manifest version, and extracts the 27 JSON files without executing extension code. No extension binary is checked in or uploaded to the public site.
- **Source provenance:** `dist/build-info.json` records `ruleSource.version`, `ruleSource.sha256`, `ruleSource.type`, and rule counts. The actual Chrome Web Store CRX tested on GitHub Actions was v6.12.8 with **7,341 definitions**. Contents can change without a source commit because the latest CRX is fetched at each build.
- **Selenium diagnostic:** `scripts/selfcheck-prepare.mjs` uses the same current CRX rules. The original **open-source** Wappalyzer engine is separately fetched from HTTPArchive only for the matching algorithm; it is not used as the technology catalog. Because the unpacked extension may receive a temporary installation ID, its runtime environment may differ from a Chrome Web Store installation; the detection engine and technology rules are taken directly from the genuine CRX.

## Automated Selenium diagnosis (no manual CSV export)

- The [Selenium Wappalyzer self-diagnosis workflow](.github/workflows/selfcheck.yml) runs after a successful build workflow and on manual dispatch only. **No cron or scheduled workflow** is configured. It runs Chromium/Selenium against `https://wappalyzer-technologies.pages.dev/` to collect the actual DOM, response headers, meta, JS globals, inline source, cookies, and CSP state.
- The exact Wappalyzer detector module is extracted from the **same Chrome Web Store CRX** as the technology JSON, without HTTPArchive fallback. Chrome for Testing launches the **actual extension** with its content/background scripts, and its native background driver returns the canonical detection result. The separate browser-signal analyzer is retained only as supplemental diagnostic data. The workflow posts a summary with detected count, missing technologies and per-channel gaps, and uploads `selenium-selfcheck` with the JSON report and raw capture.
- The workflow reads the **previous successful Selenium report** from Actions artifacts and records automatic Selenium-to-Selenium gains/losses. The original 3,361-detection manual CSV remains only a historical comparison. Subsequent gains/losses are measured **native-to-native**.
- The diagnostic fetches `/build-info.json` from the same site and reports deployed source commit and CRX version, so a Pages deployment lag or a different rule snapshot is visible.
- The public Pages site remains Functions-free; every generated HTML document is single-line. Selenium and the rule analyzer run in GitHub Actions only. The Selenium capture rejects any unexpected iframe HTTP document response or HTTP 404 response, verifies that no retired header-shard frames remain, and selects the actual top-level document response.

## Measured static iframe header-sharding experiment (2026-10-31 JST)

- Baseline actual native Wappalyzer Chrome extension: **4,224 / 7,341** definitions.
- Measured after this implementation: **4,224 / 7,341** definitions, **0 new** and **0 lost** technology names.
- In GitHub Actions Selenium, **all three** same-origin `/header-shards/01`, `/02`, `/03` iframes completed loading and each returned HTTP **200**, with its own response headers.
- **Conclusion:** Rendering the static iframe pages is feasible without Functions, but their additional response headers **did not increase the top-level Wappalyzer native detection count in this test**. Do not assume iframe response headers are aggregated into the parent tab's results.
- Cloudflare Pages serves `header-shards/01.html` at its canonical extensionless URL `/header-shards/01`; the iframe sources and `_headers` path selectors must match that URL.
- Experiment run: https://github.com/siyukatu/wappalyzer_pages/actions/runs/41084074060 ; source commit: `49be80a6082e1228a8b175b62efd1561d828d187`.
- This experiment remains in the history **only**; its runtime iframe loads and static shard assets were removed on 2026-10-31 to prevent unnecessary requests. Improvements must be evaluated with **native-to-native** counts; generated-rule estimates and the supplemental approximate analyzer do not establish detection gains.

## HTTP request suppression verification (2026-10-31)

- Older generated HTML contained **250 iframe elements**: 247 selector-derived DOM witnesses plus 3 actively loaded header-shard frames. Many selector-derived `src` values resembled non-existent relative URLs, causing HTTP 404 responses.
- The current generator omits all three header-shard frames and all `header-shards` files, retains the 247 DOM-only iframe witnesses, and enforces `frame-src 'none'` / `child-src 'none'` so that **no iframe makes an HTTP navigation**.
- Official CRX/Selenium comparison: **4,227 -> 4,227 native technology names, 0 gained, 0 lost**, **0 iframe HTTP document responses**, **0 HTTP 404 responses**, **0 third-party HTTP responses**, deployment SHA verified. See [Actions run 41189534271](https://github.com/siyukatu/wappalyzer_pages/actions/runs/41189534271) and the final restored check [41190430687](https://github.com/siyukatu/wappalyzer_pages/actions/runs/41190430687).
- Thousands of *blocked browser resource attempts* remain from synthetic script and stylesheet witness URLs. These are denied by CSP before becoming successful HTTP responses. Trials making all 7,986 `script[src]` tags inert by either unknown `type` or `nomodule` reduced CSP-blocked attempts from **8,230 to 250**, but the actual native detector **lost 199 names**. Both variants were reverted and a full native result of 4,227 was reverified; do not reintroduce them without an evidence-based preservation strategy.
- Do not re-enable shard iframe navigation, weaken CSP, or sacrifice verified native detections merely to suppress console-visible `blocked:csp` entries.

## Reusable improvement-cycle runbook

Read [the improvement-cycle manual](docs/improvement-cycle-manual.md) and [the checkpoint state](docs/improvement-cycle-state.json) to resume work in a new conversation. The manual contains the one-line invocation, required tests, native-extension regression gate, known failed experiments, and restart/stop conditions. See [AGENTS.md](AGENTS.md) for coding agents.

## Assistant-led improvement cycles

The improvement / Push / Cloudflare deployment verification / native-extension scan / next-improvement cycle is initiated and reviewed **by the assistant during an active conversation**, not by an unattended GitHub cron job. The GitHub Actions workflows provide build and Selenium measurements after each Push, and may be started manually. Continuous activity beyond the conversation is not implied.

The HTML head contains `wappalyzer-pages-commit`, `wappalyzer-pages-build-version`, `wappalyzer-pages-rules-version` and `wappalyzer-pages-rules-sha256` metadata. The Selenium stage reads the live HTML and only diagnoses it once the commit marker matches the expected deployment; stale deployments fail the bounded check rather than count as regressions.
