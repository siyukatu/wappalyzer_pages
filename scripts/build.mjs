#!/usr/bin/env node
// Generate a single intentionally synthetic Wappalyzer fingerprint page.
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { generateExtras, emitHeaders } from './enrich.mjs';
import { compileGlobals } from './globals.mjs';

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
const stripDirective = (s) => String(s).split('\\;')[0];
// Best effort regex witness; deliberately skip patterns that cannot be confidently reduced.
// Each witness is tested against the original regex, so guessed strings cannot silently pass.
function witness(raw) {
  let expression = stripDirective(raw);
  if (!expression || expression.length > 800) return null;
  try {
    let candidate = expression
      .replace(/^\^/, '').replace(/\$$/, '')
      .replace(/\\\./g, '.').replace(/\\\//g, '/').replace(/\\-/g, '-')
      .replace(/\\_/g, '_').replace(/\\:/g, ':')
      .replace(/\(\?:([^()|]+)\|[^()]*\)/g, '$1')
      .replace(/\(([^()|]+)\|[^()]*\)/g, '$1')
      .replace(/\(\?:([^()]*)\)/g, '$1')
      .replace(/\(([^()]*)\)/g, '$1')
      .replace(/\[[^\]]+\]\+/g, 'a')
      .replace(/\[[^\]]+\]\*/g, '')
      .replace(/\[[^\]]+\]/g, 'a')
      .replace(/\\d\+/g, '1').replace(/\\d/g, '1')
      .replace(/\\w\+/g, 'a').replace(/\\w/g, 'a')
      .replace(/\\s\+/g, ' ').replace(/\\s/g, ' ')
      .replace(/\\x([0-9a-f]{2})/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
      .replace(/\\u([0-9a-f]{4})/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
      .replace(/\{\d+(?:,\d*)?\}/g, '')
      .replace(/[*+?]/g, '')
      .replace(/\\([()[\]{}|?+*^$\\])/g, '$1');
    if (candidate.length > 500 || /[()[\]{}|]/.test(candidate)) return null;
    if (new RegExp(expression, 'i').test(candidate)) return candidate;
  } catch {}
  return null;
}
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
const counts = {};
const meta = new Map(), scripts = new Set(), links = new Set(), dom = new Set(), text = new Set(), globals = new Set(), htmlAttrs = new Map();
const addMeta = (name, value) => { if (name && value) { const k = name + '\0' + value; meta.set(k, [name, value]); } };
const addPath = (value) => { if (value && /^[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*){0,8}$/.test(value) && !/(?:__proto__|prototype|constructor)/.test(value)) globals.add(value); };
function addUrl(raw, kind) {
  const value = witness(raw);
  if (!value) return;
  const normalized = /^(?:https?:)?\/\//.test(value) ? value : 'https://' + value.replace(/^\/+/, '');
  if (!/^https?:\/\/[a-z0-9.-]+\//i.test(normalized) || /[\s"'<>]/.test(normalized)) return;
  (kind === 'script' ? scripts : links).add(normalized);
}
for (const [name, item] of Object.entries(all)) {
  if (!item || typeof item !== 'object') continue;
  for (const key of ['meta', 'scriptSrc', 'dom', 'js', 'html', 'text', 'css', 'cookies', 'headers']) {
    if (item[key] != null) counts[key] = (counts[key] || 0) + 1;
  }
  for (const [key, patterns] of entries(item.meta)) for (const p of values(patterns)) {
    const value = witness(p);
    if (value) addMeta(key, value);
  }
  for (const p of values(item.scriptSrc)) addUrl(p, 'script');
  for (const p of values(item.css)) addUrl(p, 'link');
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
const extras = generateExtras(all, witness);
const compactGlobals = compileGlobals(all, witness);
const bootstrap = compactGlobals.source + '\n' + extras.bootstrap;
const hash = createHash('sha256').update(bootstrap).digest('base64');
/* Static Pages cannot issue a fresh per-response nonce. Use CSP SHA-256 instead.
 * Hide the entire synthetic fingerprint body while keeping its DOM accessible.
 * The iframe/object/embed rule also protects against markup that escapes the wrapper.
 */
const concealCss = 'html,body{margin:0!important;padding:0!important}body{display:none!important}iframe,object,embed{display:none!important}';
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
await writeFile(OUT + '/index.html', html);
await writeFile(OUT + '/_headers', emitHeaders(hash, extras, styleHash));
await writeFile(OUT + '/404.html', '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>404 Not Found</title></head><body><h1>404 Not Found</h1><a href="/">Home</a></body></html>\n');
await writeFile(OUT + '/robots.txt', 'User-agent: *\nDisallow: /\n');
await writeFile(OUT + '/build-info.json', JSON.stringify({ generatedAt: new Date().toISOString(), ruleFiles: files.length, technologies: Object.keys(all).length, signatures: { meta: meta.size, scriptSrc: scripts.size, link: links.size, dom: dom.size, text: text.size, js: globals.size }, channels: counts, extras: extras.stats, globals: compactGlobals.stats }, null, 2));
console.log('Generated ' + Object.keys(all).length + ' technology candidates from ' + files.length + ' upstream JSON files.');
console.log('index.html bytes: ' + Buffer.byteLength(html));
