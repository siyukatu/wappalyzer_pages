# Wappalyzer detection-gap analysis (2026-10-30)

## Input and interpretation

- Baseline: the user-provided CSV export for `https://wappalyzer-technologies.pages.dev/`, normalized and stored in `data/detected-baseline.json`.
- Upstream: every `src/technologies/*.json` in `HTTPArchive/wappalyzer` at Pages build time.
- The baseline CSV contains **2,841 distinct detected technology names**.
- Upstream at the time of initial comparison contains **4,005 technology definitions**.
- Exactly **2,799** of the upstream names occur in the baseline after NFKC, trimming, and case-folding.
- **1,206** upstream technologies do not occur in the baseline CSV; **42** baseline names do not exactly match an upstream key. This is a *name-based* comparison, not a claim that every one of the 1,206 could be detected from a single HTML page.

For up-to-date counts and per-technology rule classifications, inspect the build artifact `dist/coverage.json`, which is regenerated from the latest upstream rules on each deployment. Counts below represent the **original** CSV, not a subsequent validation of the improvements.

## Gaps classified by rule field

Numbers can overlap because a technology can define several rule fields.

| Wappalyzer rule field | Upstream definitions absent from baseline | Static Pages action |
| --- | ---: | --- |
| `scriptSrc` | 403 | Generate regex-validated `script src` URLs; keep CSP resource loads blocked |
| `headers` | 267 | Emit validated safe synthetic response headers in `_headers`; prioritize missing names |
| `html` | 162 | Add inert raw HTML-regex witnesses in comments when parsable |
| `dom` | 161 | Add matching selectors and rule-specific attribute values |
| `js` | 142 | Compile a shared-prefix global tree with validated candidate values |
| `meta` | 102 | Emit name + regex-validated content, including presence-only meta rules |
| `cookies` | 64 | Synthesize a bounded set of first-party cookies; browser policies apply |
| `text` | 58 | Generate text witnesses; visibility and detector extraction mode can limit matches |
| `scripts` | 15 | Place regex-validated comment fingerprints inside the one CSP-hashed inline script |
| `css` | 11 | Generate CSS source references; CSP blocks loading |
| `dns` | 57 | **Not achievable** from Pages' HTML/`_headers`; requires authoritative DNS changes |
| `xhr` | 36 | Generally requires actual browser requests, deliberately avoided |
| `url` | 34 | Often requires changing the deployed URL/hostname, not just HTML |
| `probe` | 1 | Site-specific endpoint rules; test individually, avoid extra runtime requests |

The same technology may appear in multiple rows.

## Verified improvements in generated build artifacts

Comparison of the prior successful CI artifact with the updated build artifact:

| Signal | Before | After |
| --- | ---: | ---: |
| `meta` signatures | 333 | 515 |
| `scriptSrc` candidates | 1,098 | 2,166 |
| Additional DOM nodes | 1,265 | 1,459 |
| Synthetic response header fields | 75 | 220 (after missing-first prioritization) |
| Regex-validated JS global candidates | 244 | 396 |
| Inline script signature witnesses | 0 | 55 |

The latest build emits **220** synthetic HTTP header fields. These are **synthetic fingerprints emitted**, not an observed difference in Wappalyzer detections.

Example previously absent signatures now emitted: `<meta name="generator" content="Joomla!">`, Serendipity meta values, a `shopifyTag` inline script comment, and `style[data-jss]`. Browser execution and Wappalyzer's own rule confidence, dependencies, exclusions, and detection timings can still prevent detection.

## Re-test procedure

1. Deploy latest `main` on Cloudflare Pages. Confirm generated `dist/build-info.json` differs from the previous version.
2. Use Wappalyzer to export the *same* site's detected technologies to a new CSV using the same browser extension/settings.
3. Run `node scripts/compare.mjs path/to/new-export.csv`. This prints `gained`, `lost`, counts, and net change relative to the original CSV.
4. Use `dist/coverage.json` to identify remaining missing upstream rules. Prefer changes with measurable detection gain. Retain restrictive CSP to avoid third-party requests.
5. Check the real deployed response headers in the browser's Network panel. GitHub CI verifies build outputs, not Cloudflare's actual response transformations.

**Scope limits:** DNS, TLS, hosting/provider identity, URL path/hostname, external XHR/script execution, service-worker conditions, and live response-dependent signatures cannot be made universally detectable using only one static HTML page and `_headers`. The generator creates deliberate false positives and must not be used to assert that third-party technologies are installed.
