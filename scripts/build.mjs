#!/usr/bin/env node
// Generate synthetic Wappalyzer fingerprints on static Cloudflare Pages assets only.
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { generateExtras, emitHeaders } from './enrich.mjs';
import { compileGlobals } from './globals.mjs';
import { witness } from './regex-witness.mjs';
import { readFile } from 'node:fs/promises';
import { coverage } from './coverage.mjs';
import { makePassiveUrlCandidates } from './passive-urls.mjs';
import { cssFingerprints } from './css-witness.mjs';
import { fetchStoreRules } from './store-rules.mjs';
import { rootAttributes } from './root-dom.mjs';
import { generateHeaderShards } from './header-shards.mjs';

const OUT = 'dist';
const escape = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const values = (x) => Array.isArray(x) ? x : x == null ? [] : [x];
const entries = (obj) => obj && typeof obj === 'object' && !Array.isArray(obj) ? Object.entries(obj) : [];
const {files,technologies:all,downloadBytes:upstreamBytes,source:ruleSource} = await fetchStoreRules();
const baseline = JSON.parse(await readFile('data/detected-baseline.json','utf8'));
const baselineCoverage = coverage(all, baseline);
const missingBaseline = new Set(baselineCoverage.missing.map(x => x.name));
const regressed = JSON.parse(await readFile('data/detection-regressions.json','utf8'));
const gains = JSON.parse(await readFile('data/detection-gains.json','utf8'));
const lostNames = new Set(regressed.regressed);
const latestDetected = new Set([...baseline.detected.filter(n => !lostNames.has(n)),...gains.newDetected]);
const secondCoverage = coverage(all, {source:"Second exported Wappalyzer detection CSV",host:baseline.host,detected:[...latestDetected]});
const third = JSON.parse(await readFile('data/detection-delta-3.json','utf8'));
const latestNames = new Set([...latestDetected].filter(n=>!third.regressed.includes(n)).concat(third.newDetected));
const latestCoverage = coverage(all, {source:"Third exported Wappalyzer detection CSV",host:baseline.host,detected:[...latestNames]});
const missingLatest = new Set(latestCoverage.missing.map(x => x.name));
const priorityNames = new Set([...missingLatest,...third.regressed]);
const urgentNames = new Set(third.regressed);
const counts = {};
const inlineSignatures = new Set();
const meta = new Map(), scripts = new Set(), links = new Set(), dom = new Set(), text = new Set(), globals = new Set(), htmlAttrs = new Map();
const addMeta = (name, value) => { if (name && value) { const k = name + '\0' + value; meta.set(k, [name, value]); } };
const addPath = (value) => { if (value && /^[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*){0,8}$/.test(value) && !/(?:__proto__|prototype|constructor)/.test(value)) globals.add(value); };
function addUrl(raw, kind, name) {
  const choices = makePassiveUrlCandidates(raw, witness);
  const wanted = priorityNames.has(name) || regressed.regressed.includes(name) ? choices : choices.slice(0,1);
  for (const url of wanted) (kind === 'script' ? scripts : links).add(url);
}
for (const [name, item] of Object.entries(all)) {
  if (!item || typeof item !== 'object') continue;
  for (const key of ['meta', 'scriptSrc', 'dom', 'js', 'html', 'text', 'css', 'cookies', 'headers']) {
    if (item[key] != null) counts[key] = (counts[key] || 0) + 1;
  }
  for (const [key, patterns] of entries(item.meta)) for (const p of values(patterns)) {
    const value = typeof p === 'string' && p.split('\\;')[0] === '' ? '1' : witness(p);
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
const nativeCookieBaseline = JSON.parse(await readFile('data/native-cookie-priority.json','utf8'));
const nativePreserveNames = new Set([...nativeCookieBaseline.gained,...nativeCookieBaseline.lost]);
const extras = generateExtras(all, witness, priorityNames, urgentNames, nativePreserveNames);
const headerShards = generateHeaderShards(all, witness, extras.headers.lines, priorityNames, urgentNames);
const root = rootAttributes(all);
const compactGlobals = compileGlobals(all, witness);
const inlineWitnesses = [...inlineSignatures].sort().map(v => '/*' + v.replace(/\*\//g,'* /') + '*/').join('');
const bootstrap = (compactGlobals.source + ';' + extras.bootstrap + ';' + inlineWitnesses).replace(/[\r\n]/g,'');
const hash = createHash('sha256').update(bootstrap).digest('base64');
/* Static Pages cannot issue a fresh per-response nonce. Use CSP SHA-256 instead.
 * Hide the entire synthetic fingerprint body while keeping its DOM accessible.
 * The iframe/object/embed rule also protects against markup that escapes the wrapper.
 */
const cssMarkers = cssFingerprints(all, witness);
const concealCss = 'html{overflow-x:hidden!important}body{position:fixed!important;left:-200vw!important;top:0!important;width:1px!important;height:1px!important;overflow:hidden!important;opacity:0!important}iframe,object,embed{display:none!important}iframe[data-wappalyzer-header-shard]{display:block!important;position:absolute!important;left:-200vw!important;top:0!important;width:1px!important;height:1px!important;border:0!important;opacity:0!important;pointer-events:none!important}' + cssMarkers.css;
const styleHash = createHash('sha256').update(concealCss).digest('base64');
const sourceCommit = process.env.CF_PAGES_COMMIT_SHA || process.env.GITHUB_SHA || 'local';
const pageBuildVersion = '5';
const deploymentMeta = '<meta name="wappalyzer-pages-commit" content="'+escape(sourceCommit)+'">'+
  '<meta name="wappalyzer-pages-build-version" content="'+pageBuildVersion+'">'+
  '<meta name="wappalyzer-pages-rules-version" content="'+escape(ruleSource.version)+'">'+
  '<meta name="wappalyzer-pages-rules-sha256" content="'+escape(ruleSource.sha256)+'">';
const html = '<!doctype html>\n<html lang="en"'+root.html+'><head><meta charset="utf-8">'+deploymentMeta+'\n' +
  '<title>Wappalyzer fingerprint benchmark (synthetic)</title>\n' +
  '<meta name="robots" content="noindex,nofollow,noarchive">\n' +
  '<style id="wappalyzer-conceal">' + concealCss + '</style>\n' +
  [...meta.values()].flatMap(([name,val]) => {
    const kinds = /^(?:og:|article:|fb:|al:|twitter:)/i.test(name) ? ['property','name'] : ['name'];
    return kinds.map(kind => '<meta '+kind+'="'+escape(name)+'" content="'+escape(val)+'">');
  }).join('') +
  [...links].map((url) => '<link rel="stylesheet" href="' + escape(url) + '">').join('\n') + '\n' +
  [...scripts].map((url) => '<script src="' + escape(url) + '"></script>').join('\n') + '\n' +
  '<script>' + bootstrap.replace(/<\/script/gi, '<\\/script') + '</script>\n</head><body'+root.body+'>\n' +
  '<!-- Synthetic signatures only; named technologies are NOT necessarily installed. -->\n' +
  '<div id="wappalyzer-fingerprints">\n' +
  extras.body + '\n' +
  [...dom].join('\n') + '\n<div>' + [...text].map(escape).join(' ') + '</div>\n' +
  '</div>\n' +
  headerShards.shards.map(shard => '<iframe data-wappalyzer-header-shard="" src="/'+shard.path+'" title="Synthetic header fingerprint shard" loading="eager" referrerpolicy="no-referrer" tabindex="-1" aria-hidden="true"></iframe>').join('') +
  '</body></html>\n';
// All dynamic content is emitted at build time; no Cloudflare Functions.
await mkdir(OUT, { recursive: true });
// Compress only the emitted HTML; preserve quoted attribute values and CSP hashes.
const compactHtml = html.replace(/[\r\n]/g,'');
if (/[\r\n]/.test(compactHtml)) throw new Error('index.html must be one line');
await writeFile(OUT + '/index.html', compactHtml);
await writeFile(OUT + '/_headers', emitHeaders(hash, extras, styleHash, headerShards.shards));
await mkdir(OUT + '/header-shards', { recursive: true });
for (const shard of headerShards.shards) await writeFile(OUT + '/' + shard.path, shard.html);
await writeFile(OUT + '/404.html', '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>404 Not Found</title></head><body><h1>404 Not Found</h1><a href="/">Home</a></body></html>');
await writeFile(OUT + '/robots.txt', 'User-agent: *\nDisallow: /\n');
await writeFile(OUT + '/coverage.json', JSON.stringify(latestCoverage, null, 2));
await writeFile(OUT + '/coverage-original.json', JSON.stringify(baselineCoverage, null, 2));
await writeFile(OUT + '/coverage-second.json', JSON.stringify(secondCoverage, null, 2));
await writeFile(OUT + '/build-info.json', JSON.stringify({ generatedAt: new Date().toISOString(), sourceCommit, pageBuildVersion, ruleFiles: files.length, upstreamArchiveBytes: upstreamBytes, ruleSource, technologies: Object.keys(all).length, signatures: { meta: meta.size, scriptSrc: scripts.size, link: links.size, dom: dom.size, text: text.size, js: compactGlobals.stats.globalPaths, scriptText: inlineSignatures.size, cssRules: cssMarkers.rules, regressedPrioritized: regressed.regressed.length, latestRegressedPrioritized: third.regressed.length }, channels: counts, extras: extras.stats, headerShards:headerShards.stats, root:root.stats, globals: compactGlobals.stats }, null, 2));
console.log('Generated ' + Object.keys(all).length + ' technology candidates from Chrome Web Store Wappalyzer v' + ruleSource.version + ' (' + files.length + ' JSON files).');
console.log('index.html bytes: ' + Buffer.byteLength(compactHtml));
