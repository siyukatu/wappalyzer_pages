#!/usr/bin/env node
// Promote detections returned by the REAL Chrome extension background driver.
// Never equate the older approximated Selenium signal analyzer with this result.
import {readFile,writeFile,appendFile} from 'node:fs/promises';
const out=process.env.DIAGNOSTIC_DIR||'.selfcheck';
const load=async p=>JSON.parse(await readFile(p,'utf8'));
const [probe,report,rules]=await Promise.all([
  load(out+'/extension-probe.json'),load(out+'/report.json'),load(out+'/rules.json')
]);
const normalized=s=>String(s||'').normalize('NFKC').trim().toLocaleLowerCase('en');
const detections=Array.isArray(probe.nativeDetections)?probe.nativeDetections:[];
const names=new Map(detections.filter(x=>x&&typeof x.name==='string'&&x.name)
  .map(x=>[normalized(x.name),x]));
if(probe.nativeError||names.size<1000)
  throw new Error('Actual CRX background driver did not provide usable native detections: '+
    (probe.nativeError||('count='+names.size)));
const sourceNames=Object.keys(rules);
const missing=sourceNames.filter(n=>!names.has(normalized(n)));
const fields=['headers','cookies','dom','js','scriptSrc','html','meta','text','scripts','css','url','dns','xhr','probe','certIssuer','robots'];
const byChannel=Object.fromEntries(fields.map(key=>[key,missing.filter(name=>rules[name]?.[key]!=null).length]));
const prior=await load(out+'/previous-report.json').catch(e=>e.code==='ENOENT'?null:Promise.reject(e));
const oldNative=prior?.nativeExtension?.technologies||[];
const oldNames=new Map(oldNative.filter(x=>x?.name).map(x=>[normalized(x.name),x.name]));
const gains=[...names].filter(([key])=>!oldNames.has(key)).map(([,v])=>v.name).sort();
const losses=[...oldNames].filter(([key])=>!names.has(key)).map(([,v])=>v).sort();
const trend=oldNative.length?{
  prior:oldNames.size,current:names.size,net:names.size-oldNames.size,
  gained:gains,lost:losses,priorTimestamp:prior.generatedAt
}:null;
report.approximateSeleniumScan={
  count:report.technologies.length,
  warning:'Diagnostic only: manually collected browser evidence, not an official extension result.'
};
report.nativeExtension={
  engine:'Exact Chrome Web Store CRX (content.js/background.js/js/wappalyzer.js) executed inside Chrome for Testing',
  detected:names.size,
  extensionId:probe.extensions?.[0]||null,
  extensionVersion:report.ruleSource.version,
  engineSha256:report.ruleSource.detectorEngineSha256,
  warning:'Loaded from genuine CRX ZIP as an unpacked Chrome extension; its generated installation ID can differ from Chrome Web Store.',
  backgroundError:probe.nativeError||null,
  sampling:probe.nativeSampling||null,
  detectionTimeline:probe.nativeTimeline||[],
  injectionDiagnostics:probe.injectionDiagnostics||null,
  technologies:[...names.values()].sort((a,b)=>a.name.localeCompare(b.name)),
  missingTechnologyNames:missing,
  missingByChannel:byChannel,
  trend
};
report.engine='Actual Wappalyzer extension background driver (native resolved detections)';
report.caveat='Same CRX technology files, matching module and live content/background scripts; unpacked extension ID may differ from the signed Web Store installation.';
report.summary={
  ...report.summary,
  detected: names.size,
  priorExtensionDetected:trend?.prior??null,
  nativeNetChange:trend?.net??null,
  gained:trend?.gained||[],
  lost:trend?.lost||[],
  missingFromCRX:missing.length,
  approximateDetectorCount:report.approximateSeleniumScan.count
};
report.generatedAt=new Date().toISOString();
await writeFile(out+'/report.json',JSON.stringify(report,null,2));
const md=[
  '# Actual Wappalyzer extension self-diagnosis','',
  '**URL:** '+report.url,
  '**Scan:** '+report.generatedAt,
  '**CRX version:** '+report.ruleSource.version,
  '**Engine:** Actual Wappalyzer extension content script + background driver, not an emulation.',
  '**Deployed commit:** '+(report.deployment?.sourceCommit||'unavailable'),
  '**Verified Pages commit:** '+Boolean(report.deployment?.isLatestCommit),
  '**Native extension ID:** '+(probe.extensions?.[0]||'missing'),
  '',
  '| Metric | Value |','| --- | ---: |',
  '| Chrome Web Store CRX technology definitions | '+sourceNames.length+' |',
  '| **Native Wappalyzer detections (peak snapshot)** | **'+names.size+'** |',
  '| Initial sampled count | '+(probe.nativeSampling?.firstCount??'N/A')+' |',
  '| Last sampled count | '+(probe.nativeSampling?.lastCount??'N/A')+' |',
  '| Initial native Wappalyzer badge | '+(probe.nativeSampling?.firstBadgeCount??'N/A')+' |',
  '| Latest native Wappalyzer badge | '+(probe.nativeSampling?.lastBadgeCount??'N/A')+' |',
  '| Peak native Wappalyzer badge | '+(probe.nativeSampling?.peakBadgeCount??'N/A')+' |',
  '| Initial raw detection records | '+(probe.nativeSampling?.firstRawMatches??'N/A')+' |',
  '| Latest raw detection records | '+(probe.nativeSampling?.lastRawMatches??'N/A')+' |',
  '| Peak raw detection records | '+(probe.nativeSampling?.peakRawMatches??'N/A')+' |',
  '| Background API available at last query | '+(probe.nativeSampling?.backgroundUnavailableAtEnd?'no; using last valid native result':'yes')+' |',
  '| Scan duration after page load (seconds) | '+(probe.nativeSampling?.durationSeconds??'N/A')+' |',
  '| Sampling stabilized | '+(probe.nativeSampling?.stabilized?'yes':'no; max time reached')+' |',
  '| JS script console mentions | '+(probe.injectionDiagnostics?.jsJsConsoleMentions??'not observed')+' |',
  '| DOM script console mentions | '+(probe.injectionDiagnostics?.domJsConsoleMentions??'not observed')+' |',
  '| Undetected CRX definitions | '+missing.length+' |',
  '| Old approximate Selenium detector (not comparable) | '+report.approximateSeleniumScan.count+' |',
  '| Previous native extension scan | '+(trend?.prior??'first native scan')+' |',
  '| **Native-to-native change** | **'+(trend?((trend.net>=0?'+':'')+trend.net):'baseline')+'** |',
  '| Native additions | '+(trend?.gained.length??'N/A')+' |',
  '| Native losses | '+(trend?.lost.length??'N/A')+' |',
  '| CSP-blocked browser requests | '+report.browser.cspBlockedRequests+' |',
  '',
  '## Detection counts over time','',
  '| Seconds after load | Resolved names | Toolbar badge | Raw evidence records | Background response |',
  '| ---: | ---: | ---: | ---: | :--- |',
  ...(probe.nativeTimeline||[]).map(p=>'| '+p.secondsAfterPageLoad+' | '+(p.detected??'N/A')+' | '+(p.badgeCount??'N/A')+' | '+(p.tabRawMatches??'N/A')+' | '+(p.nativeQueryOk?'OK':(p.error||'not requested'))+' |'),
  '',
  'Note: two dom.js console messages can represent re-analysis, not two unique detected technologies. Results are deduplicated by name.',
  '',
  '## New native detections (first 50)','',
  ...(trend?gains.slice(0,50).map(x=>'- '+x):['First native run; the next scan will contain a direct comparison.']),'',
  '## Lost native detections (first 50)','',
  ...(trend?losses.slice(0,50).map(x=>'- '+x):['First native run; no comparison available.']),'',
  '## Undetected CRX technology rules by channel','',
  '| Channel | Missing definitions |','| --- | ---: |',
  ...Object.entries(byChannel).sort((a,b)=>b[1]-a[1]).map(([k,v])=>'| '+k+' | '+v+' |'),
  '',
  '## First 70 undetected technology names','',
  ...missing.slice(0,70).map(n=>'- '+n),
  '',
  'Full resolved technology list, rule gaps, version metadata, and previous-run changes are available in selenium-selfcheck/report.json.',
  'This is the native Wappalyzer CRX detection result. The extension was unpacked for use by Chrome for Testing.',
  ''
].join('\n');
await writeFile(out+'/summary.md',md);
if(process.env.GITHUB_STEP_SUMMARY)await appendFile(process.env.GITHUB_STEP_SUMMARY,md);
console.log(JSON.stringify({
  nativeDetected:names.size,crxDefinitions:sourceNames.length,nativeMissing:missing.length,
  previousNative:trend?.prior??null,nativeChange:trend?.net??null,
  gained:trend?.gained.length??null,lost:trend?.lost.length??null,
  approximateDetector:report.approximateSeleniumScan.count,
  deploymentSha:report.deployment?.sourceCommit,crxVersion:report.ruleSource.version,
  firstCount:probe.nativeSampling?.firstCount,lastCount:probe.nativeSampling?.lastCount,
  durationSeconds:probe.nativeSampling?.durationSeconds,
  badgeInitial:probe.nativeSampling?.firstBadgeCount,
  badgeLast:probe.nativeSampling?.lastBadgeCount,
  badgePeak:probe.nativeSampling?.peakBadgeCount,
  rawFirst:probe.nativeSampling?.firstRawMatches,
  rawLast:probe.nativeSampling?.lastRawMatches,
  stabilized:probe.nativeSampling?.stabilized,
  domJsConsoleMentions:probe.injectionDiagnostics?.domJsConsoleMentions
}));
