#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Script } from 'node:vm';
const [html,headers,info,coverage,notFound] = await Promise.all([
  readFile('dist/index.html','utf8'),
  readFile('dist/_headers','utf8'),
  readFile('dist/build-info.json','utf8').then(JSON.parse),
  readFile('dist/coverage.json','utf8').then(JSON.parse),
  readFile('dist/404.html','utf8'),
]);
const digest = s => createHash('sha256').update(s).digest('base64');
const style=/<style id="wappalyzer-conceal">([\s\S]*?)<\/style>/.exec(html)?.[1];
const head=html.slice(0,html.indexOf('</head>'));
const scripts=[...head.matchAll(/<script>([\s\S]*?)<\/script>/gi)].map(m=>m[1]);
assert.ok(style,'Concealment style missing');
assert.match(head,/<meta name="wappalyzer-pages-commit" content="[^"]+">/);
assert.ok(head.includes('<meta name="wappalyzer-pages-rules-version" content="'+info.ruleSource.version+'">'));
assert.ok(head.includes('<meta name="wappalyzer-pages-rules-sha256" content="'+info.ruleSource.sha256+'">'));
assert.equal(typeof info.pageBuildVersion,'string');
assert.ok(info.root?.rootSelectorsEmitted>=5,'Document-root DOM fingerprints were not synthesized');
assert.match(html,/<html lang="en"[^>]*(?:class|data-[a-z-]+)=/,'Actual html element lacks synthetic DOM fingerprints');
assert.match(html,/<body[^>]+(?:class|data-[a-z-]+)=/,'Actual body element lacks synthetic DOM fingerprints');
assert.ok(!/[\r\n]/.test(html),'index.html must be exactly one physical line');
assert.ok(!/[\r\n]/.test(notFound),'404.html must be exactly one physical line');
assert.ok(!/body\{display:none/.test(style),'Body must remain text-detectable while visually hidden');
assert.equal(scripts.length,2,'Expect bootstrap and separate CSP-hashed script witnesses in the head');
assert.ok(headers.includes("style-src 'sha256-"+digest(style)+"'"),'CSS CSP hash mismatch');
assert.ok(headers.includes("script-src 'sha256-"+digest(scripts[0])+"' 'sha256-"+digest(scripts[1])+"'"),'JS CSP hashes mismatch');
assert.match(scripts[1],/^\/\*[^]*\*\/$/,'Second inline script must be comment-only witnesses');
const cookieWrites=[];
const sandbox={document:{set cookie(value){cookieWrites.push(value)},get cookie(){return ''}}};
new Script(scripts[0],{filename:'wappalyzer-bootstrap.js'}).runInNewContext(sandbox,{timeout:5000});
assert.ok(cookieWrites.length>=100,'Cookie fingerprint bootstrap did not execute');
assert.ok(Object.keys(sandbox).length>300,'Global fingerprint bootstrap did not execute');
assert.match(headers,/connect-src 'none'/);
assert.match(headers,/frame-src 'none'/);
assert.match(headers,/child-src 'none'/);
assert.match(headers,/frame-ancestors 'self'/);
assert.match(headers,/connect-src 'none'/);
assert.match(headers,/X-Frame-Options: SAMEORIGIN/);
assert.match(html,/<div id="wappalyzer-fingerprints">/);
assert.ok(!/<div id="wappalyzer-fingerprints"[^>]*hidden/.test(html),'Detector must not exclude text under hidden attribute');
assert.match(notFound,/<title>404 Not Found<\/title>/);
assert.equal(info.ruleSource?.type,'chrome-web-store-crx','Must use Chrome Web Store CRX, not GitHub archive');
assert.equal(info.ruleSource?.extensionId,'gppongmhjkpfnbhagpmjfkannfbllamg','Unexpected extension ID');
assert.match(info.ruleSource?.version||'',/^\d+\.\d+\.\d+(?:\.\d+)?$/,'Missing extension version');
assert.match(info.ruleSource?.sha256||'',/^[a-f0-9]{64}$/,'Missing CRX content hash');
assert.equal(info.ruleFiles,27,'Chrome Web Store CRX must contain all 27 technology JSONs');
assert.ok(info.technologies>=7000,'Newest Chrome Web Store CRX technology catalog appears incomplete');
assert.equal(info.ruleSource?.technologies,info.technologies,'Manifest source-count mismatch');
assert.ok(info.signatures.meta>=300,'Too few meta signatures');
assert.ok(info.signatures.scriptSrc>=1000,'Too few script source signatures');
assert.ok(info.signatures.scriptText>=10,'Inline signature generation failed');
assert.ok(info.signatures.regressedPrioritized===138,'Lost-technology prioritization disabled');
assert.equal(coverage.baselineCount,3361,'Latest Wappalyzer CSV not selected');
assert.equal(info.signatures.latestRegressedPrioritized,20,'Third-scan regression prioritization missing');
assert.ok(info.extras.syntheticHeaderFields>=220,'Too few synthetic response-header fields');
assert.equal(info.headerShards?.count,0,'No header-shard iframe loads are allowed');
const sections=new Map();
let current=null;
for(const line of headers.split('\n')) {
  if(!line.trim()) continue;
  if(!line.startsWith(' ')) { current=line; assert.ok(!sections.has(current),'Duplicate _headers path rule'); sections.set(current,[]); }
  else { assert.ok(current,'Header without a path rule'); sections.get(current).push(line); }
}
assert.ok(sections.has('/*') && sections.has('/') && sections.has('/index.html'),'Missing static security/root rules');
assert.deepEqual(sections.get('/'),sections.get('/index.html'),'Root and /index.html fingerprints differ');
assert.ok(sections.get('/').length>=220,'Root header fingerprints missing');
assert.equal(sections.size,3,'Unexpected _headers rule count');
assert.ok(!headers.includes('/header-shards/'),'Unused iframe header path rules remain');
assert.ok(!html.includes('data-wappalyzer-header-shard'),'Header-shard iframe would trigger requests');
assert.ok(html.includes('<iframe'),'Keep DOM-only iframe fingerprints for detection');
await assert.rejects(stat('dist/header-shards'), {code:'ENOENT'}, 'Unused static header-shards directory remains');
assert.ok(sections.size<=100,'Cloudflare Pages maximum 100 _headers rules');
assert.equal((html.match(/<iframe data-wappalyzer-header-shard=/g)||[]).length,0,'Unexpected header shard iframe');
assert.equal(coverage.upstreamCount,info.technologies,'coverage count mismatch');
assert.ok(coverage.upstreamNotInBaseline>0);
assert.ok((await stat('dist/index.html')).size <=25*1024*1024,'Pages asset size limit');
for(const line of headers.split('\n'))assert.ok(line.length<=2000,'Pages _headers line too long');
console.log(JSON.stringify({
  upstream:info.technologies,baselineDetected:coverage.baselineCount,
  missingLatest:coverage.upstreamNotInBaseline,signatureCounts:info.signatures,
  bytes:(await stat('dist/index.html')).size,headerShards:info.headerShards
},null,2));
