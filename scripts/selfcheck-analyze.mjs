#!/usr/bin/env node
// Apply the HTTPArchive open-source Wappalyzer engine to Selenium observations.
import { readFile, writeFile, mkdir, appendFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const folder = process.env.DIAGNOSTIC_DIR || '.selfcheck';
const load = async name => JSON.parse(await readFile(name,'utf8'));
const [observed, rules, categories, old, gains, losses, third] = await Promise.all([
  load(folder+'/capture.json'),load(folder+'/rules.json'),load(folder+'/categories.json'),
  load('data/detected-baseline.json'),load('data/detection-gains.json'),
  load('data/detection-regressions.json'),load('data/detection-delta-3.json')
]);
const engine = require('../'+folder+'/engine.cjs');
engine.setCategories(categories);
engine.setTechnologies(rules);
const all=[...new Map([
  ...engine.technologies,
  ...engine.requires.flatMap(v=>v.technologies),
  ...engine.categoryRequires.flatMap(v=>v.technologies)
].map(v=>[v.name,v])).values()];
const lookup = new Map(all.map(v=>[v.name,v]));
const normalize = value => String(value).normalize('NFKC').trim().toLocaleLowerCase('en');
const inputs = {
  html:observed.html||'',text:observed.text||'',css:observed.css||'',
  headers:observed.headers||{},cookies:observed.cookies||{},
  meta:observed.meta||{},scriptSrc:observed.scriptSrc||[],
  scripts:observed.scripts||'',url:observed.url||''
};
const detections=engine.analyze(inputs,all);
let jsSignals=0,domSignals=0;
for(const t of all) {
  const found={};
  for(const chain of Object.keys(t.js||{}))
    if(Object.hasOwn(observed.js||{},chain))found[chain]=observed.js[chain];
  if(Object.keys(found).length){
    detections.push(...engine.analyzeManyToMany(t,'js',found));
    jsSignals+=Object.keys(found).length;
  }
}
for(const signal of observed.dom||[]) {
  const tech=lookup.get(signal.name);
  if(!tech || !Object.hasOwn(tech.dom||{},signal.selector))continue;
  for(const key of ['exists','text','property','attribute']) {
    if(!Object.hasOwn(signal,key))continue;
    const section=key==='property'?'properties':key==='attribute'?'attributes':key;
    const type=(key==='property'||key==='attribute')
      ?'dom.'+section+'.'+signal[key]:'dom.'+section;
    const value=key==='exists'?'':key==='text'?signal.text:signal.value;
    try {
      detections.push(...engine.analyzeManyToMany(tech,type,{[signal.selector]:[value]}));
      domSignals++;
    }catch{}
  }
}
// Prevent false positives from technologies that require a missing parent.
let active=new Set(detections.map(x=>x.technology.name));
for(let pass=0;pass<12;pass++){
  const next=new Set();
  for(const item of detections){
    const t=item.technology;
    if(t.requires?.some(x=>!active.has(x.name)))continue;
    if(t.requiresCategory?.some(x=>![...active].some(n=>
      lookup.get(n)?.categories?.includes(Number(x.id)))))continue;
    next.add(t.name);
  }
  const stable=active.size===next.size&&[...next].every(n=>active.has(n));
  active=next;
  if(stable)break;
}
const qualified=detections.filter(x=>active.has(x.technology.name));
let resolved;
try { resolved=engine.resolve(qualified); }
catch(e) {
  console.warn('Engine resolve fallback:',String(e));
  resolved=[...new Map(qualified.map(x=>[x.technology.name,{
    name:x.technology.name,confidence:x.pattern.confidence||100,version:x.version||''
  }])).values()];
}
const technologies=resolved.map(item=>({
  name:item.name,confidence:item.confidence||100,version:item.version||'',
  channels:[...new Set(qualified.filter(x=>x.technology.name===item.name)
    .map(x=>x.pattern.type))].sort()
})).sort((a,b)=>a.name.localeCompare(b.name));
const detected=new Map(technologies.map(x=>[normalize(x.name),x.name]));
let previousSelfcheck=null;
try { previousSelfcheck=JSON.parse(await readFile(folder+'/previous-report.json','utf8')); }
catch(error){ if(error.code!=='ENOENT')console.warn('Invalid previous selfcheck:',String(error)); }
const previousSeleniumDetected=new Map(
  (previousSelfcheck?.technologies||[]).map(x=>[normalize(x.name),x.name])
);
const seleniumTrend=previousSelfcheck && previousSeleniumDetected.size
  ? {
      previousTimestamp:previousSelfcheck.generatedAt,
      previousCount:previousSeleniumDetected.size,
      currentCount:technologies.length,
      netChange:technologies.length-previousSeleniumDetected.size,
      gained:[...detected].filter(([key])=>!previousSeleniumDetected.has(key)).map(([,name])=>name).sort(),
      lost:[...previousSeleniumDetected].filter(([key])=>!detected.has(key)).map(([,name])=>name).sort()
    }
  : null;
const prior=new Map(old.detected.map(n=>[normalize(n),n]));
for(const n of losses.regressed)prior.delete(normalize(n));
for(const n of gains.newDetected)prior.set(normalize(n),n);
for(const n of third.regressed)prior.delete(normalize(n));
for(const n of third.newDetected)prior.set(normalize(n),n);
if(prior.size!==3361)throw new Error('Expected latest historical CSV total of 3361, got '+prior.size);
const gained=[...detected].filter(([k])=>!prior.has(k)).map(([,n])=>n).sort();
const missing=[...prior].filter(([k])=>!detected.has(k)).map(([,n])=>n).sort();
const sourceMissing=Object.keys(rules).filter(n=>!detected.has(normalize(n)));
const fields=['scriptSrc','js','headers','dom','html','meta','cookies','text','scripts','css','url','xhr','dns'];
const byChannel=Object.fromEntries(fields.map(k=>[k,sourceMissing.filter(n=>rules[n]?.[k]!=null).length]));
const matchedChannels={};
for(const t of technologies)for(const k of t.channels)matchedChannels[k]=(matchedChannels[k]||0)+1;
const result={
  generatedAt:new Date().toISOString(),url:observed.url,
  engine:'Selenium Chrome + HTTPArchive archived open-source Wappalyzer engine',
  caveat:'This is not the current proprietary browser extension; results are not directly equivalent to a Wappalyzer CSV export.',
  summary:{lastManualCsv:prior.size,seleniumDetected:technologies.length,
    netDifference:technologies.length-prior.size,
    seleniumOnlyCount:gained.length,manualCsvOnlyCount:missing.length,
    seleniumOnly:gained,manualCsvOnly:missing},
  seleniumTrend,
  browser:observed.diagnostics,
  engineEvidence:{upstreamTechnologyCount:all.length,rawMatches:qualified.length,jsSignals,domSignals,matchedChannels},
  remaining:{count:sourceMissing.length,byChannel,technologies:sourceMissing},
  technologies
};
await mkdir(folder,{recursive:true});
await writeFile(folder+'/report.json',JSON.stringify(result,null,2));
const md=[
  '# Selenium technology self-diagnosis','',
  '**URL:** '+observed.url,
  '**When:** '+result.generatedAt,
  '**Detector:** HTTPArchive original open-source Wappalyzer core with live Selenium observations.',
  '',
  '> This is not the proprietary commercial Wappalyzer extension. Counts may differ, especially for probes, DNS, XHR and timing.','',
  '| Metric | Count |','| --- | ---: |',
  '| Previous manual CSV | '+prior.size+' |',
  '| Selenium-inferred technologies | '+technologies.length+' |',
  '| Prior Selenium result | '+(seleniumTrend?seleniumTrend.previousCount:'first run')+' |',
  '| Selenium-to-Selenium net change | '+(seleniumTrend?((seleniumTrend.netChange>=0?'+':'')+seleniumTrend.netChange):'not yet available')+' |',
  '| Found only by Selenium | '+gained.length+' |',
  '| Found only in manual CSV | '+missing.length+' |',
  '| Missing upstream rule matches | '+sourceMissing.length+' |',
  '| Real response header fields | '+observed.diagnostics.responseHeaders+' |',
  '| Browser cookie names | '+observed.diagnostics.cookieCount+' |',
  '| JavaScript global paths observed | '+observed.diagnostics.globalPaths+' |',
  '| CSP-blocked browser requests | '+observed.diagnostics.cspBlockedRequests+' |',
  '| Third-party successful responses | '+observed.diagnostics.thirdPartyResponses.length+' |','',
  '**CSP verified:** '+observed.diagnostics.cspBlocksExternal,
  '**Selenium-to-Selenium newly detected:** '+(seleniumTrend?seleniumTrend.gained.length:'N/A'),
  '**Selenium-to-Selenium lost detections:** '+(seleniumTrend?seleniumTrend.lost.length:'N/A'),
  '**Concealment applied:** '+observed.diagnostics.cspStyleApplied,'',
  '## Trend: technology names gained since previous Selenium scan (first 50)','',
  ...(seleniumTrend?seleniumTrend.gained.slice(0,50).map(x=>'- '+x):['No previous Selenium result yet.']),'',
  '## Trend: technology names lost since previous Selenium scan (first 50)','',
  ...(seleniumTrend?seleniumTrend.lost.slice(0,50).map(x=>'- '+x):['No previous Selenium result yet.']),'',
  '## In manual CSV but not Selenium (first 50)','',
  ...missing.slice(0,50).map(x=>'- '+x),'',
  '## Selenium-only detections (first 50)','',
  ...gained.slice(0,50).map(x=>'- '+x),'',
  '## Missing upstream technology names by channel','',
  '| Channel | Missing technologies |','| --- | ---: |',
  ...Object.entries(byChannel).sort((a,b)=>b[1]-a[1]).map(([key,value])=>'| '+key+' | '+value+' |'),
  '',
  'The full list of detections, missing technologies and browser observations is in the Actions artifact.',''
].join('\n');
await writeFile(folder+'/summary.md',md);
if(process.env.GITHUB_STEP_SUMMARY)await appendFile(process.env.GITHUB_STEP_SUMMARY,md);
console.log(JSON.stringify({seleniumDetected:technologies.length,manualBaseline:prior.size,
  seleniumOnly:gained.length,manualOnly:missing.length,sourceMissing:sourceMissing.length,
  seleniumTrendNet:seleniumTrend?.netChange??null,
  jsSignals,domSignals,headers:observed.diagnostics.responseHeaders}));
