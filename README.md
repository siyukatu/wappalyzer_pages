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
