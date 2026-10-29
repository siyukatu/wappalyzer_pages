# Second Wappalyzer scan — detection recovery and static optimization

Baseline URL: https://wappalyzer-technologies.pages.dev/

## Actual detections from the user-provided CSVs

| Comparison | Unique technology names |
| --- | ---: |
| First export | 2,841 |
| Second export | 3,161 |
| Newly detected in second export | 458 |
| No longer detected in second export | 138 |
| Net difference | +320 |

The second export corresponds to the HTML text file supplied with it (approximately 250,022 bytes and more than 3,000 newline characters). This repository does not assume the live Pages deployment already includes the later code improvements.

## Latest rule coverage (Wappalyzer main, 4,005 definitions)

- 3,119 upstream names exactly match the second CSV after Unicode NFKC and case normalization.
- 886 upstream names are absent from the second CSV; 42 CSV names have no exact upstream key (renames/aliases or differing catalog snapshots are possible).
- Of the 886 absent upstream definitions, 794 contain at least one static HTML/JS/CSS/Cookie or response-header detection channel; 82 have only network-type channels; 10 have no direct matchable fingerprint field.
- Among the remaining 886 definitions, 234 have `scriptSrc`, 214 `headers`, 164 `js`, 118 `dom`, 117 `html`, 57 `text`, 51 `cookies`, 34 `meta`, and 9 `css`. These buckets overlap and are not additive.

A first pass over 9 technology-definition JSON files showed that 49 of 64 regressed names in those files contained `scriptSrc` signatures. Therefore, malformed-but-regex-matching URL witnesses must **not** be discarded merely because the host is invalid.

## Implemented changes

1. **Single-line HTML:** the generated index and 404 pages have no CR/LF bytes. Syntactic whitespace required in attribute values and script comments is preserved.
2. **One upstream fetch:** the current Wappalyzer main branch is fetched as a single tar.gz from GitHub codeload; the builder extracts all technology JSON files. This avoids the GitHub API's HTTP 403 rate limit encountered during rapid CI builds.
3. **Legacy + relative scriptSrc witnesses:** the script URL generator retains strings that match the original regex, even if they are invalid as URLs. For technologies that regressed, it can emit both a legacy absolute witness and a relative witness.
4. **DOM + text:** handles simple descendant/child selector chains, DOM-rule text, and enhanced attribute rules. The page is visually blank via offscreen/opacity styling rather than `body{display:none}`, preserving text for DOM APIs.
5. **CSS:** adds regex-validated passive CSS selectors and custom properties, authorized by the SHA-256 CSP style hash.
6. **Social meta:** adds both `name` and `property` variants for Open Graph and related metadata.
7. **Globals:** compresses shared-prefix paths and removes empty object leaf overhead (global-tree JSON reduced from 83,005 to 64,489 bytes in the latest generated artifact).
8. **Cookies:** attempts 160 prioritized, first-party Secure/SameSite cookie signatures instead of 90.
9. **Headers and CSP:** continues to generate `_headers` without Cloudflare Functions, protecting against outbound requests and dangerous header modifications.
10. **Regression controls:** `data/detection-regressions.json` and `data/detection-gains.json` encode the 138 lost / 458 gained names. `scripts/compare.mjs` uses the second export by default; `--original` compares to the first export.

## Build verification

GitHub Actions checks the CSP SHA-256 values, all-pages static constraints, single-line output, presence of coverage data, and the inline JavaScript bootstrap in an isolated Node.js VM. The HTML produced by one successful intermediate build was 319,699 bytes, with no CR/LF bytes. A larger raw file than the uploaded historical HTML is expected because it now contains more distinct fingerprint signatures; the markup itself has been compacted.

**Crucial distinction:** increased generated matches do not prove increased Wappalyzer detections. Re-export the live site after the latest Cloudflare Pages deploy and use:

```sh
node scripts/compare.mjs ./export-after-deployment.csv
```

To compare against the first scan instead:

```sh
node scripts/compare.mjs ./export-after-deployment.csv --original
```

Inspect `dist/coverage.json` for remaining missing definitions and `dist/build-info.json` for generation metrics. Limits: DNS/MX/TLS, actual server identity, URL paths, running third-party code, and live XHR cannot be universally forged by static Cloudflare Pages HTML. No Cloudflare Functions or external runtime requests are used.
