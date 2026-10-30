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
  // Try extending the selected header without displacing any of its matches.
  // Unlike the first pass, this starts from the previously selected result,
  // so extra witnesses cannot replace previously matched technology names.
  const protectedNames = new Set(bestScore.names);
  const appendable = [...new Set(compiled.filter(x=>!x.start&&!x.end).map(x=>x.value))]
    .filter(v=>v && !best.includes(v))
    .sort((a,b)=>a.length-b.length || a.localeCompare(b));
  for(let round=0;round<35;round++) {
    let next=null;
    for(const value of appendable) {
      if(best.includes(value))continue;
      const trial=best ? best+', '+value : value;
      if(trial.length>MAX_VALUE)continue;
      const matches=coverage(trial);
      if(matches.technologies<=bestScore.technologies)continue;
      if([...protectedNames].some(name=>!matches.names.includes(name)))continue;
      if(!next || matches.technologies>next.matches.technologies ||
        (matches.technologies===next.matches.technologies && trial.length<next.value.length))
        next={value:trial,matches};
    }
    if(!next)break;
    best=next.value;
    bestScore=next.matches;
  }
  return {value:best,baseline:before.technologies,matched:bestScore.technologies,
    names:bestScore.names};
}


// Add more fingerprints without displacing an already-matching end-anchored
// rule. Via: "[\d.-]+ vegur$" (Heroku) is a concrete case: concatenating
// after "vegur" loses Heroku even when other technologies are gained.
export function augmentBeforeAnchoredSuffix(rules,current,maxLength=1700) {
  const compiled=[];
  for(const {regexp,value,techName} of rules){
    try{
      const regex=new RegExp(regexp,'i');
      if(regex.test(value))compiled.push({regex,value,name:techName,
        anchoredEnd:/(?<!\\)\$$/.test(regexp)});
    }catch{}
  }
  const matched=value=>{
    const names=new Set();
    for(const item of compiled) if(item.regex.test(value))names.add(item.name);
    return names;
  };
  const protectedNames=matched(current);
  const suffix=compiled.filter(item=>item.anchoredEnd&&item.regex.test(current)&&current.endsWith(item.value))
    .sort((a,b)=>b.value.length-a.value.length)[0];
  if(!suffix)return{value:current,before:protectedNames.size,after:protectedNames.size,added:[]};
  const suffixText=suffix.value;
  let body=current.slice(0,-suffixText.length).replace(/,\s*$/,'');
  let best=current;
  let bestNames=protectedNames;
  const witnesses=[...new Set(compiled.map(x=>x.value))]
    .filter(v=>v && v!==suffixText && v.length<250)
    .sort((a,b)=>a.length-b.length);
  for(let round=0;round<25;round++){
    let next=null,top=bestNames;
    for(const v of witnesses){
      if(body.includes(v))continue;
      const trial=(body?body+', ':'')+v+', '+suffixText;
      if(trial.length>maxLength)continue;
      const hits=matched(trial);
      if([...protectedNames].some(name=>!hits.has(name)))continue;
      if(hits.size>top.size||(hits.size===top.size&&next&&trial.length<next.value.length)){
        if(hits.size<=bestNames.size)continue;
        next={value:trial,body:(body?body+', ':'')+v,names:hits};top=hits;
      }
    }
    if(!next)break;
    best=next.value;body=next.body;bestNames=next.names;
  }
  return {value:best,before:protectedNames.size,after:bestNames.size,
    added:[...bestNames].filter(x=>!protectedNames.has(x))};
}
