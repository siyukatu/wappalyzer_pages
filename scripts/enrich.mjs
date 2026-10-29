// Additional static-only fingerprint channels for Cloudflare Pages.
// Signatures are synthetic and must NEVER be interpreted as installed software.
const SKIP_HEADERS = new Set([
  'content-security-policy','content-security-policy-report-only',
  'content-type','content-length','content-encoding','transfer-encoding',
  'cache-control','etag','last-modified','vary','location','server','date',
  'connection','keep-alive','set-cookie','access-control-allow-origin',
  'access-control-allow-credentials','access-control-allow-methods',
  'access-control-allow-headers','strict-transport-security',
  'x-frame-options','x-content-type-options','x-robots-tag','referrer-policy',
  'permissions-policy','clear-site-data','www-authenticate','refresh',
  'report-to','nel','link','content-disposition'
]);
const values = (v) => Array.isArray(v) ? v : v == null ? [] : [v];
const entries = (v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.entries(v) : [];
const escaped = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const plain = (v) => typeof v === 'string' && /^[\x20-\x7e]{1,250}$/.test(v) && !v.includes('<!--') && !v.includes('-->');
const prohibitedGlobal = new Set([
  'window','document','self','top','parent','frames','location','navigator',
  'history','origin','localStorage','sessionStorage','indexedDB','fetch',
  'XMLHttpRequest','Object','Array','String','Number','Boolean','Function',
  'Promise','Math','JSON','Reflect','Symbol','Proxy','console','performance',
  'eval','alert','open','close','name','caches','crypto','customElements',
  'screen','Storage','WebSocket','EventSource','HTMLElement','HTMLDocument'
]);
function selectorMarkup(raw) {
  if (typeof raw !== 'string' || raw.length > 250) return null;
  // One compound selector. Skip combinators and pseudo selectors rather
  // than claim matches for complex DOM relationships we cannot satisfy.
  const s = raw.trim();
  if (/[>:~+]/.test(s) || /\s(?![^\[]*\])/.test(s)) return null;
  const tag = s.match(/^[a-z][a-z0-9-]*/i)?.[0] || 'div';
  if (['html','body','head','meta','title','base','style'].includes(tag.toLowerCase())) return null;
  const ids = [...s.matchAll(/#([a-z_][\w-]*)/ig)].map(m=>m[1]);
  const classes = [...s.matchAll(/\.([a-z_][\w-]*)/ig)].map(m=>m[1]);
  const attrs = [];
  const re = /\[([a-z_:][\w:.-]*)(?:([*^$|~]?=)\s*(['"]?)([^"'\\\]]*)\3)?\]/ig;
  for (const m of s.matchAll(re)) {
    const key = m[1].toLowerCase();
    if (key.startsWith('on') || ['srcdoc','style','integrity','nonce'].includes(key)) continue;
    // Attribute selectors are represented by their matchable substrings.
    const value = m[4] || 'fingerprint';
    if (!plain(value)) continue;
    attrs.push([m[1], m[2] === '$=' ? 'fp-' + value : m[2] === '^=' ? value + '-fp' : value]);
  }
  if (ids.length) attrs.push(['id',ids[0]]);
  if (classes.length) attrs.push(['class',classes.join(' ')]);
  const as = attrs.slice(0,8).map(([k,v]) => ' ' + k + '="' + escaped(v) + '"').join('');
  const voids = new Set(['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']);
  const safeTag = /^[a-z][a-z0-9-]{0,35}$/i.test(tag) ? tag : 'div';
  return voids.has(safeTag) ? '<' + safeTag + as + '>' : '<' + safeTag + as + '></' + safeTag + '>';
}
function selectHeaders(all, witness, cap = 18000) {
  const patterns = new Map();
  for (const tech of Object.values(all)) {
    for (const [name, raw] of entries(tech?.headers)) {
      const lower = name.toLowerCase();
      if (!/^[a-z][a-z0-9-]{0,60}$/i.test(name) || SKIP_HEADERS.has(lower) ||
          lower.startsWith('cf-') || lower.startsWith('access-control-')) continue;
      for (const p of values(raw)) {
        if (typeof p !== 'string' || p.length > 700) continue;
        const v = witness(p);
        if (!plain(v) || v.length > 250 || !/^[\x20-\x7e]+$/.test(v)) continue;
        if (!patterns.has(lower)) patterns.set(lower, { name, rules: [] });
        patterns.get(lower).rules.push({ regexp: p.split('\\;')[0], value: v });
      }
    }
  }
  const candidates = [];
  for (const {name, rules} of patterns.values()) {
    const regexes = rules.map(({regexp})=>{try{return new RegExp(regexp,'i')}catch{return null}}).filter(Boolean);
    if (!regexes.length) continue;
    let best = '';
    let score = 0;
    // Find a high-coverage single value, then greedily append values only
    // when appending increases the number of independently matching patterns.
    const distinct = [...new Set(rules.map(r => r.value))].sort((a,b) => a.length-b.length).slice(0,250);
    const coverage = v => regexes.reduce((n,re) => n + Number(re.test(v)),0);
    for (const v of distinct) {
      const count = coverage(v);
      if (count > score || (count === score && (!best || v.length < best.length))) { best = v; score = count; }
    }
    for (let round=0; round<40; round++) {
      let next = best, count = score;
      for (const v of distinct) {
        if (best.includes(v)) continue;
        const possible = best + ', ' + v;
        if (possible.length > 1700) continue;
        const hits = coverage(possible);
        if (hits > count) { next = possible; count = hits; }
      }
      if (next === best) break;
      best = next; score = count;
    }
    if (best) candidates.push({name, best, score, size: name.length+best.length+4});
  }
  // Valuable uncommon header fields are retained as long as the practical
  // response-size budget holds. A huge response can fail at upstream proxies.
  candidates.sort((a,b) => b.score / b.size - a.score / a.size || a.name.localeCompare(b.name));
  const lines = [];
  let total = 0, score = 0;
  for (const c of candidates) {
    if (total + c.size > cap || c.size > 1950 || lines.length >= 150) continue;
    lines.push('  ' + c.name + ': ' + c.best);
    total += c.size;
    score += c.score;
  }
  return {lines, count:lines.length, approxMatches:score, bytes:total};
}
export function generateExtras(all, witness) {
  const dom = new Set(), comments = new Set(), cookieValues = new Map(), js = new Map();
  let domRuleCount = 0, cookieRuleCount=0;
  for (const tech of Object.values(all)) {
    const dr = tech?.dom;
    const selectors = typeof dr === 'string' || Array.isArray(dr) ? values(dr) : Object.keys(dr || {});
    for (const sel of selectors) {
      domRuleCount++;
      // Selector lists split on commas outside complex selectors.
      for (const piece of String(sel).split(/,(?![^\[]*\])/)) {
        const markup = selectorMarkup(piece);
        if (markup) dom.add(markup);
      }
    }
    for (const rule of values(tech?.html)) {
      const sample = witness(rule);
      if (plain(sample) && sample.length <= 180 && comments.size < 8000) comments.add(sample);
    }
    for (const [name, raw] of entries(tech?.cookies)) {
      cookieRuleCount++;
      if (!/^[a-z0-9_!#$%&'*+.^|~-]{1,80}$/i.test(name)) continue;
      const sample = values(raw).map(witness).find(v => typeof v === 'string' && /^[a-z0-9_.-]{1,80}$/i.test(v)) || '1';
      if (!cookieValues.has(name)) cookieValues.set(name, sample);
    }

  }
  const cookieList = [...cookieValues].slice(0,90);
  const cookieScript = 'for(const [name,value] of ' + JSON.stringify(cookieList) +
    '){try{document.cookie=name+"="+encodeURIComponent(value)+"; Path=/; SameSite=Lax";}catch{}}\n';
  const headers = selectHeaders(all,witness);
  const body = '<!-- Additional simple DOM selectors generated from upstream rules -->\n' + [...dom].join('\n') +
    '\n<!-- Literal HTML-regex witnesses (inert comments; not active code) -->\n' +
    [...comments].map(c=>'<!-- signature: ' + c + ' -->').join('\n');
  return {
    bootstrap: cookieScript,
    body, headers,
    stats: {additionalDom:dom.size, htmlComments:comments.size, cookies:cookieList.length, upstreamDomSelectors:domRuleCount, upstreamCookieRules:cookieRuleCount,
      syntheticHeaderFields: headers.count, syntheticHeaderMatches:headers.approxMatches, syntheticHeaderBytes: headers.bytes}
  };
}
export function emitHeaders(hash, extras, styleHash) {
  const csp = [
    "default-src 'none'", "script-src 'sha256-" + hash + "'",
    "script-src-attr 'none'", "style-src 'sha256-" + styleHash + "'", "style-src-attr 'none'", "img-src 'none'",
    "font-src 'none'", "connect-src 'none'", "frame-src 'none'",
    "child-src 'none'", "worker-src 'none'", "media-src 'none'",
    "manifest-src 'none'", "object-src 'none'", "form-action 'none'",
    "base-uri 'none'", "frame-ancestors 'none'"
  ].join('; ');
  const lines = [
    '/*',
    '  Content-Security-Policy: ' + csp,
    '  X-Frame-Options: DENY',
    '  X-Content-Type-Options: nosniff',
    '  Referrer-Policy: no-referrer',
    '  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    '  X-Robots-Tag: noindex, nofollow, noarchive',
    '  Cache-Control: public, max-age=0, must-revalidate',
    ...extras.headers.lines
  ];
  if (lines.some(line=>line.length>2000)) throw new Error('_headers line exceeds Cloudflare Pages limit');
  return lines.join('\n') + '\n';
}
