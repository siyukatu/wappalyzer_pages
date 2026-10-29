# Wappalyzer fingerprint Pages

Synthetic fingerprint benchmark: downloads **all** JSON files currently in [HTTPArchive/wappalyzer/src/technologies](https://github.com/HTTPArchive/wappalyzer/tree/main/src/technologies) **at build time**, then generates one HTML document containing as many passive detection signatures as practical.

> **Warning:** This is a deliberately misleading fingerprint benchmark, **not** evidence that a listed technology is installed. It will not trigger every Wappalyzer rule: HTTP headers, DNS, cookies, TLS, live network traffic, and difficult regular expressions cannot all be represented faithfully in one HTML file. Actual detector output depends on Wappalyzer version and browser CSP handling.

## Cloudflare Pages

- Connect this repository using **Workers & Pages → Create → Pages → Connect to Git**.
- Production branch: `main`
- Framework preset: **None**
- Build command: `npm run build`
- Build output directory: `dist`
- Node.js version: 20 or later

Every Cloudflare Pages build downloads a single GitHub codeload `main` branch tar.gz archive and extracts **every** `src/technologies/*.json` rule file. This avoids unauthenticated GitHub API rate limits and reduces upstream fetches to **one** build-time request. No source rules are checked into this repository. Failed downloads **fail the build** rather than publish an incomplete result. For automatic upstream refresh, configure a Cloudflare Pages deploy hook and call it on a schedule.

The generated `dist/index.html` is a single standalone HTML file. Cloudflare Pages applies `dist/_headers`, whose CSP denies all outbound network requests (`default-src 'none'`, `connect-src 'none'`, etc.) and permits only a hash-verified inline script for synthetic JavaScript globals. Script and stylesheet URLs in the document are intentionally non-functional: CSP blocks them.

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

Cloudflare documents a limit of 100 matching rules and 2,000 characters per header line. This build uses a **single** `/*` rule, with each line kept within the limit. Cloudflare Pages currently limits static file size to 25 MiB. There is no `functions/` or `_worker.js`.

Documentation: https://developers.cloudflare.com/pages/configuration/headers/ and https://developers.cloudflare.com/pages/configuration/serving-pages/

## Invisible fingerprint page

The generated index uses a SHA-256-authorized inline `<style id="wappalyzer-conceal">` that moves the body offscreen, clips it, and makes it transparent while **preserving text exposure to DOM readers**. It blocks iframe/object/embed rendering. A `hidden` wrapper offers an additional fallback when this style is unavailable and is overridden only by the trusted style when applied. The CSP `style-src` permits **only the SHA-256 hash** of this exact generated style, without `unsafe-inline`. A fixed nonce would not provide meaningful request-specific security on a static Cloudflare Pages deployment. JavaScript remains governed by a separate hashed `script-src` directive. No Functions are needed.

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
- Up to **160** Secure/SameSite first-party cookies are attempted, prioritized toward previously missing technologies; this can change browser cookie state.
- External script/stylesheet URLs are **intentionally not fetched**. If a malformed URL is a useful Wappalyzer signature it is retained; outbound requests remain forbidden by CSP.
- GitHub Actions verifies single-line markup, CSP hashes, page limits, and executes the synthetic bootstrap in a restricted Node VM to catch runtime errors. True Wappalyzer detections still require re-exporting the live page after Cloudflare deploys.

The [second-scan assessment](docs/second-scan.md) describes the measured 458 gained / 138 lost and known remaining limitations.
