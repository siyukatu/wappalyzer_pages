#!/usr/bin/env node
// Generate a single intentionally synthetic Wappalyzer fingerprint page.
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { generateExtras, emitHeaders } from './enrich.mjs';
import { compileGlobals } from './globals.mjs';
import { witness } from './regex-witness.mjs';
import { readFile } from 'node:fs/promises';
import { coverage } from './coverage.mjs';
import { makePassiveUrlCandidates } from './passive-urls.mjs';
import { cssFingerprints } from './css-witness.mjs';

const API = 'https://api.github.com/repos/HTTPArchive/wappalyzer/contents/src/technologies?ref=main';
const OUT = 'dist';
const headers = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'wappalyzer-pages-builder' };
const get = async (url) => {
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw new Error('Fetch failed: ' + response.status + ' ' + url);
  return response.json();
};
const escape = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const values = (x) => Array.isArray(x) ? x : x == null ? [] : [x];
const entries = (obj) => obj && typeof obj === 'object' && !Array.isArray(obj) ? Object.entries(obj) : [];
const unique = (arr) => [...new Set(arr)];
const listing = await get(API);
const files = listing.filter((f) => f.type === 'file' && f.name.endsWith('.json')).sort((a, b) => a.name.localeCompare(b.name));
if (files.length < 20) throw new Error('Unexpectedly small rule list; refusing partial build');
const all = {};
// Limit concurrency to reduce upstream load.
for (let i = 0; i < files.length; i += 5) {
  await Promise.all(files.slice(i, i + 5).map(async (file) => {
    const data = await get(file.download_url);
    Object.assign(all, data);
  }));
}
const baseline = JSON.parse(await readFile('data/detected-baseline.json','utf8'));
const baselineCoverage = coverage(all, baseline);
const missingBaseline = new Set(baselineCoverage.missing.map(x => x.name));
const regressed = JSON.parse(await readFile('data/detection-regressions.json','utf8'));
const gains = JSON.parse(await readFile('data/detection-gains.json','utf8'));
const lostNames = new Set(regressed.regressed);
const latestDetected = new Set([...baseline.detected.filter(n => !lostNames.has(n)),...gains.newDetected]);
const latestCoverage = coverage(all, {source:"Second exported Wappalyzer detection CSV",host:baseline.host,detected:[...latestDetected]});
const missingLatest = new Set(latestCoverage.missing.map(x => x.name));
const priorityNames = new Set([...missingLatest,...regressed.regressed]);
const counts = {};
const inlineSignatures = new Set();
const meta = new Map(), scripts = new Set(), links = new Set(), dom = new Set(), text = new Set(), globals = new Set(), htmlAttrs = new Map();
const addMeta = (name, value) => { if (name && value) { const k = name + '\0' + value; meta.set(k, [name, value]); } };
const addPath = (value) => { if (value && /^[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*){0,8}$/.test(value) && !/(?:__proto__|prototype|constructor)/.test(value)) globals.add(value); };
function addUrl(raw, kind, name) {
  const choices = makePassiveUrlCandidates(raw, witness);
  const wanted = regressed.regressed.includes(name) ? choices : choices.slice(0,1);
  for (const url of wanted) (kind === 'script' ? scripts : links).add(url);
}
for (const [name, item] of Object.entries(all)) {
  if (!item || typeof item !== 'object') continue;
  for (const key of ['meta', 'scriptSrc', 'dom', 'js', 'html', 'text', 'css', 'cookies', 'headers']) {
    if (item[key] != null) counts[key] = (counts[key] || 0) + 1;
  }
  for (const [key, patterns] of entries(item.meta)) for (const p of values(patterns)) {
    const value = p === '' ? '1' : witness(p);
    if (value) addMeta(key, value);
  }
  for (const p of values(item.scriptSrc)) addUrl(p, 'script', name);
  for (const p of values(item.scripts)) { const v = witness(p); if (v && !v.includes('*/') && v.length < 300) inlineSignatures.add(v); }
  for (const p of values(item.css)) addUrl(p, 'link', name);
  for (const [path] of entries(item.js)) addPath(path);
  for (const p of values(item.text)) { const v = witness(p); if (v && v.length < 100) text.add(v); }
  for (const p of values(item.html)) { const v = witness(p); if (v && v.length < 100) text.add(v); }
  // DOM selector injection is intentionally conservative: only simple tag/class/id selectors.
  const domRules = typeof item.dom === 'string' || Array.isArray(item.dom) ? values(item.dom) : Object.keys(item.dom || {});
  for (const selector of domRules) {
    for (const candidate of String(selector).split(',')) {
      const s = candidate.trim();
      if (/^[a-z][a-z0-9-]*$/i.test(s)) dom.add('<' + s + '></' + s + '>');
      else if (/^\.[a-z][\w-]*$/i.test(s)) dom.add('<div class="' + escape(s.slice(1)) + '"></div>');
      else if (/^#[a-z][\w-]*$/i.test(s)) dom.add('<div id="' + escape(s.slice(1)) + '"></div>');
    }
  }
}
const extras = generateExtras(all, witness, priorityNames);
const compactGlobals = compileGlobals(all, witness);
const inlineWitnesses = [...inlineSignatures].sort().map(v => '/*' + v.replace(/\*\//g,'* /') + '*/').join('');
const bootstrap = (compactGlobals.source + ';' + extras.bootstrap + ';' + inlineWitnesses).replace(/[\r\n]/g,'');
const hash = createHash('sha256').update(bootstrap).digest('base64');
/* Static Pages cannot issue a fresh per-response nonce. Use CSP SHA-256 instead.
 * Hide the entire synthetic fingerprint body while keeping its DOM accessible.
 * The iframe/object/embed rule also protects against markup that escapes the wrapper.
 */
const cssMarkers = cssFingerprints(all, witness);
const concealCss = 'html{overflow-x:hidden!important}body{position:fixed!important;left:-200vw!important;top:0!important;width:1px!important;height:1px!important;overflow:hidden!important;opacity:0!important}#wappalyzer-fingerprints[hidden]{display:block!important}iframe,object,embed{display:none!important}' + cssMarkers.css;
const styleHash = createHash('sha256').update(concealCss).digest('base64');
const html = '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n' +
  '<title>Wappalyzer fingerprint benchmark (synthetic)</title>\n' +
  '<meta name="robots" content="noindex,nofollow,noarchive">\n' +
  '<style id="wappalyzer-conceal">' + concealCss + '</style>\n' +
  [...meta.values()].map(([name, val]) => '<meta name="' + escape(name) + '" content="' + escape(val) + '">').join('\n') + '\n' +
  [...links].map((url) => '<link rel="stylesheet" href="' + escape(url) + '">').join('\n') + '\n' +
  [...scripts].map((url) => '<script src="' + escape(url) + '"></script>').join('\n') + '\n' +
  '<script>' + bootstrap.replace(/<\/script/gi, '<\\/script') + '</script>\n</head><body>\n' +
  '<!-- Synthetic signatures only; named technologies are NOT necessarily installed. -->\n' +
  '<div id="wappalyzer-fingerprints" hidden>\n' +
  extras.body + '\n' +
  [...dom].join('\n') + '\n<div hidden>' + [...text].map(escape).join(' ') + '</div>\n' +
  '</div>\n</body></html>\n';
// All dynamic content is emitted at build time; no Cloudflare Functions.
await mkdir(OUT, { recursive: true });
// Compress only the emitted HTML; preserve quoted attribute values and CSP hashes.
const compactHtml = html.replace(/[\r\n]/g,'');
if (/[\r\n]/.test(compactHtml)) throw new Error('index.html must be one line');
await writeFile(OUT + '/index.html', compactHtml);
await writeFile(OUT + '/_headers', emitHeaders(hash, extras, styleHash));
await writeFile(OUT + '/404.html', '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>404 Not Found</title></head><body><h1>404 Not Found</h1><a href="/">Home</a></body></html>');
await writeFile(OUT + '/robots.txt', 'User-agent: *\nDisallow: /\n');
await writeFile(OUT + '/coverage.json', JSON.stringify(latestCoverage, null, 2));
await writeFile(OUT + '/coverage-original.json', JSON.stringify(baselineCoverage, null, 2));
await writeFile(OUT + '/build-info.json', JSON.stringify({ generatedAt: new Date().toISOString(), ruleFiles: files.length, technologies: Object.keys(all).length, signatures: { meta: meta.size, scriptSrc: scripts.size, link: links.size, dom: dom.size, text: text.size, js: compactGlobals.stats.globalPaths, scriptText: inlineSignatures.size, cssRules: cssMarkers.rules, regressedPrioritized: regressed.regressed.length }, channels: counts, extras: extras.stats, globals: compactGlobals.stats }, null, 2));
console.log('Generated ' + Object.keys(all).length + ' technology candidates from ' + files.length + ' upstream JSON files.');
console.log('index.html bytes: ' + Buffer.byteLength(compactHtml));
