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

Every Cloudflare Pages build fetches the upstream rule directory, then downloads the JSON files (up to five concurrent HTTP requests). No source rules are checked into this repository. Failed downloads **fail the build** rather than publish an incomplete result. For automatic upstream refresh, configure a Cloudflare Pages deploy hook and call it on a schedule.

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

The generated index now contains an inline `<style id="wappalyzer-conceal">` that applies `body { display: none !important }` and hides `iframe`, `object`, and `embed` elements explicitly. Fingerprint DOM nodes remain in the source and in the document. A `hidden` wrapper offers an additional fallback. The CSP `style-src` permits **only the SHA-256 hash** of this exact generated style, without `unsafe-inline`. A fixed nonce would not provide meaningful request-specific security on a static Cloudflare Pages deployment. JavaScript remains governed by a separate hashed `script-src` directive. No Functions are needed.

## Compact global fingerprint synthesis

`scripts/globals.mjs` generates **one prefix-sharing property tree** from all `js` technology rules instead of repeating JavaScript assignments or maintaining two independent lists. Candidate values are verified against the source rule's regular expression; unsupported patterns fall back to an object placeholder. Unsafe global names and prototype-sensitive keys are skipped. Nested paths preserve their parent object shape, and the one-page CSP script hash is recalculated at each build.

`dist/build-info.json` reports `globals.globalPaths`, `globals.globalPatternMatches`, `globals.globalTreeBytes` and `globals.globalScriptBytes`. These are generation metrics, not confirmed Wappalyzer detections.
