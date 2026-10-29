// Build-time comparison with user-supplied Wappalyzer export.
// This is a historical observation: it is NOT a fresh detection test.
export function coverage(all, baseline) {
  const normalized = s => String(s).normalize('NFKC').trim().toLocaleLowerCase('en');
  const found=new Set(baseline.detected.map(normalized));
  const source=new Map(Object.keys(all).map(n=>[normalized(n),n]));
  const staticTypes=['meta','dom','js','html','text','scriptSrc','scripts','css','cookies','headers'];
  const networkTypes=['dns','xhr','probe','robots','url','certIssuer','cert','headers','http'];
  const categories={
    staticCandidates:[],
    headerOnly:[],
    networkOnly:[],
    noDirectSignature:[],
  };
  const missing=[];
  const byChannel={};
  for(const [name,rule] of Object.entries(all)) {
    if(found.has(normalized(name)))continue;
    const stat=staticTypes.filter(k=>rule[k]!=null);
    const net=networkTypes.filter(k=>rule[k]!=null);
    const missingRow={name,static:stat,network:net};
    missing.push(missingRow);
    if(stat.length)categories.staticCandidates.push(name);
    else if(net.length)categories.networkOnly.push(name);
    else categories.noDirectSignature.push(name);
    if(stat.length===1&&stat[0]==='headers')categories.headerOnly.push(name);
    for(const signal of [...new Set([...stat,...net])])byChannel[signal]=(byChannel[signal]||0)+1;
  }
  const onlyFromCsv=baseline.detected.filter(n=>!source.has(normalized(n)));
  const matched=Object.keys(all).length-missing.length;
  return {
    generatedAt:new Date().toISOString(), baselineSource:baseline.source,
    baselineSite:baseline.host, baselineCount:baseline.detected.length,
    upstreamCount:Object.keys(all).length,
    exactNormalizedNameMatches:matched,
    upstreamNotInBaseline:missing.length,
    csvNamesNotInUpstream:onlyFromCsv.length,
    unmatchedCsvExamples:onlyFromCsv.slice(0,50),
    categories:Object.fromEntries(Object.entries(categories).map(([k,v])=>[k,{count:v.length,examples:v.slice(0,50)}])),
    missingRulesByChannel:byChannel,
    missing,
    caveat:"Historical CSV comparison only; real new detections require another Wappalyzer export after deployment."
  };
}
