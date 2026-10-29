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
assert.ok(!/[\r\n]/.test(html),'index.html must be exactly one physical line');
assert.ok(!/[\r\n]/.test(notFound),'404.html must be exactly one physical line');
assert.ok(!/body\{display:none/.test(style),'Body must remain text-detectable while visually hidden');
assert.equal(scripts.length,1,'Expect one CSP-authorized bootstrap in the head');
assert.ok(headers.includes("style-src 'sha256-"+digest(style)+"'"),'CSS CSP hash mismatch');
assert.ok(headers.includes("script-src 'sha256-"+digest(scripts[0])+"'"),'JS CSP hash mismatch');
const cookieWrites=[];
const sandbox={document:{set cookie(value){cookieWrites.push(value)},get cookie(){return ''}}};
new Script(scripts[0],{filename:'wappalyzer-bootstrap.js'}).runInNewContext(sandbox,{timeout:5000});
assert.ok(cookieWrites.length>=100,'Cookie fingerprint bootstrap did not execute');
assert.ok(Object.keys(sandbox).length>300,'Global fingerprint bootstrap did not execute');
assert.match(headers,/connect-src 'none'/);
assert.match(headers,/frame-src 'none'/);
assert.match(html,/wappalyzer-fingerprints" hidden/);
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
assert.equal(coverage.upstreamCount,info.technologies,'coverage count mismatch');
assert.ok(coverage.upstreamNotInBaseline>0);
assert.ok((await stat('dist/index.html')).size <=25*1024*1024,'Pages asset size limit');
for(const line of headers.split('\n'))assert.ok(line.length<=2000,'Pages _headers line too long');
console.log(JSON.stringify({
  upstream:info.technologies,baselineDetected:coverage.baselineCount,
  missingLatest:coverage.upstreamNotInBaseline,signatureCounts:info.signatures,
  bytes:(await stat('dist/index.html')).size
},null,2));
