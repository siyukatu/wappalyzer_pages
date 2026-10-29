// Pack a shared response-header value so that one field detects many technologies.
// Wappalyzer sees a single string for X-Powered-By (not separate lines).
// Strict ^...$ rules such as NodeBB cannot share a value with other products,
// so we optimize distinct detected names rather than individual pattern counts.
const MAX_VALUE=1700;
function testMatches(compiled,value) {
  const found=new Set();
  let weighted=0;
  for(const rule of compiled) {
    if(found.has(rule.name))continue;
    try {
      if(rule.regex.test(value)) {found.add(rule.name);weighted+=rule.weight;}
    }catch{}
  }
  return {technologies:found.size,weighted,names:[...found]};
}
export function optimizeSharedHeader(rules,current) {
  const compiled=[];
  for(const {regexp,value,techName,weight=1} of rules){
    if(typeof regexp!=='string'||typeof value!=='string'||!techName)continue;
    try{
      const regex=new RegExp(regexp,'i');
      if(regex.test(value)) compiled.push({regex,value,name:techName,weight,
        start:regexp.startsWith('^'),end:/(?<!\\)\$$/.test(regexp)});
    }catch{}
  }
  if(!compiled.length) return {value:current,baseline:0,matched:0,names:[]};
  const coverage=value=>testMatches(compiled,value);
  const before=coverage(current);
  const witnessValues=[...new Set(compiled.filter(x=>!x.start&&!x.end).map(x=>x.value))]
    .sort((a,b)=>a.length-b.length||a.localeCompare(b)).slice(0,450);
  // Start with a low-conflict, unanchored value. Starting from NodeBB's
  // ^NodeBB$ would permanently prevent all other fingerprints from joining.
  let text='',score=0;
  for(let round=0;round<90;round++){
    let next=text,top=score;
    for(const candidate of witnessValues){
      if(!candidate||text.includes(candidate))continue;
      const trial=text?text+', '+candidate:candidate;
      if(trial.length>MAX_VALUE)continue;
      const matched=coverage(trial).technologies;
      if(matched>top || matched===top&&matched>score&&trial.length<next.length){
        next=trial;top=matched;
      }
    }
    if(next===text)break;
    text=next;score=top;
  }
  // Include at most one anchored prefix, e.g. ^PHP or ^Next.js.
  // Suffix-anchored patterns can sometimes coexist at the end as well.
  const prefixes=[...new Set(compiled.filter(x=>x.start&&!x.end).map(x=>x.value))];
  const suffixes=[...new Set(compiled.filter(x=>!x.start&&x.end).map(x=>x.value))];
  const variants=[current,text,...prefixes.map(v=>text?v+', '+text:v)];
  let best=current,bestScore=before;
  for(const v of variants) {
    if(!v || v.length>MAX_VALUE)continue;
    const m=coverage(v);
    if(m.technologies>bestScore.technologies||
       m.technologies===bestScore.technologies && m.weighted>bestScore.weighted) {
      best=v;bestScore=m;
    }
  }
  for(const ending of suffixes){
    const value=best?best+', '+ending:ending;
    if(value.length>MAX_VALUE)continue;
    const match=coverage(value);
    if(match.technologies>bestScore.technologies) {best=value;bestScore=match;}
  }
  return {value:best,baseline:before.technologies,matched:bestScore.technologies,
    names:bestScore.names};
}
