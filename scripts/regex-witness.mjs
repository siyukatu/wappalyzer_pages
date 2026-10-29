// Produce candidate strings for Wappalyzer regexes without executing any remote code.
// Every returned witness is checked against its source regex. Unsupported patterns
// return null rather than claiming a detection.
const directive = s => String(s).split('\\;')[0];
const valid = s => typeof s === 'string' && s.length > 0 && s.length < 800 && !/[\r\n\x00-\x08]/.test(s);
const LIMIT = 64;
function choices(strings) {
  return [...new Set(strings.filter(s => s.length <= 500))].slice(0, LIMIT);
}
function product(a,b) {
  const result=[];
  for(const x of a) for(const y of b) {
    if ((x+y).length <= 500) result.push(x+y);
    if (result.length >= LIMIT) return choices(result);
  }
  return choices(result);
}
function chooseClass(contents) {
  const negated=contents.startsWith('^');
  if(negated)return ['x','a','1'];
  const out=[];
  if(contents.includes('\\d') || contents.includes('0-9'))out.push('1','0');
  if(contents.includes('\\w') || /a-z|A-Z/.test(contents))out.push('a','A');
  if(contents.includes('\\s'))out.push(' ');
  for(let i=0;i<contents.length;i++){
    const c=contents[i];
    if(c==='\\' && i+1<contents.length){
      const v=contents[++i];
      if(v==='.')out.push('.');
      else if(v==='-')out.push('-');
      else if(!'dswDSW'.includes(v))out.push(v);
    }else if(c!==']'&&c!=='-'&&c!=='^')out.push(c);
  }
  return choices(out.length?out:['a']);
}
function sampleRegex(source) {
  let at=0;
  function seq(end) {
    let list=[''];
    while(at<source.length && source[at]!==end && source[at]!=='|') {
      let out=atom();
      if(source[at]==='?' || source[at]==='*' || source[at]==='+') {
        const q=source[at++];
        out=q==='?'||q==='*'?choices(['',...out]):out;
        if(source[at]==='?')at++;
      } else if(source[at]==='{') {
        const m=/^\{(\d+)(?:,(\d*))?\}(\?)?/.exec(source.slice(at));
        if(m){
          at+=m[0].length;
          const n=Math.min(10,Number(m[1]));
          out=n===0?choices(['',...out]):out.map(v=>v.repeat(n));
        }
      }
      list=product(list,out);
      if(!list.length)return [];
    }
    return list;
  }
  function alt(end) {
    let result=[];
    while(at<source.length) {
      result.push(...seq(end));
      if(source[at]!=='|')break;
      at++;
      if(result.length>LIMIT*3)break;
    }
    return choices(result);
  }
  function atom() {
    const c=source[at++];
    if(c==='^'||c==='$')return [''];
    if(c==='.')return ['a'];
    if(c==='\\'){
      const v=source[at++]||'';
      if(v==='d')return ['1'];
      if(v==='w')return ['a'];
      if(v==='s')return [' '];
      if(v==='D')return ['a'];
      if(v==='W')return ['-'];
      if(v==='S')return ['a'];
      if(v==='x' && /^[0-9a-f]{2}/i.test(source.slice(at,at+2))) {
        const ch=String.fromCharCode(parseInt(source.slice(at,at+2),16));at+=2;return [ch];
      }
      if(v==='u' && /^[0-9a-f]{4}/i.test(source.slice(at,at+4))) {
        const ch=String.fromCharCode(parseInt(source.slice(at,at+4),16));at+=4;return [ch];
      }
      if(/^[1-9]$/.test(v))return ['','a','1'];
      if(v==='b'||v==='B'||v==='A'||v==='Z')return [''];
      return [v];
    }
    if(c==='['){
      let chars='',escaped=false;
      while(at<source.length){
        const x=source[at++];
        if(x===']'&&!escaped)break;
        chars+=x;
        escaped=x==='\\'&&!escaped;
        if(x!=='\\')escaped=false;
      }
      return chooseClass(chars);
    }
    if(c==='('){
      let lookaround=false;
      if(source[at]==='?'){
        at++;
        if(source[at]===':' || source[at]==='>' ) at++;
        else if(source[at]==='=' || source[at]==='!'){lookaround=true;at++;}
        else if(source[at]==='<'){
          at++;
          if(source[at]==='='||source[at]==='!'){lookaround=true;at++;}
          else {while(at<source.length&&source[at]!=='>')at++;if(source[at]==='>')at++;}
        }else{
          while(at<source.length&&source[at]!==':'&&source[at]!==')')at++;
          if(source[at]===':')at++;
        }
      }
      const got=alt(')');
      if(source[at]===')')at++;
      return lookaround?['']:got.length?got:[''];
    }
    return [c];
  }
  return alt('');
}
export function witness(input) {
  if(typeof input!=='string')return null;
  const pattern=directive(input);
  if(!valid(pattern) || pattern.length>900)return null;
  let regex;
  try{regex=new RegExp(pattern,'i');}catch{return null;}
  if(pattern==='')return null;
  try {
    // Prefer shorter candidates: reduce expensive DOM and response payloads.
    const list=sampleRegex(pattern).sort((a,b)=>a.length-b.length);
    for(const c of list)if(c&&valid(c)&&regex.test(c))return c;
    // Some lookaround/backreference expressions need a broader literal context.
    for(const c of list){
      for(const pre of ['','a','https://','<div ','/']){
        for(const post of ['','a','>','/','.js']){
          const s=pre+c+post;
          if(valid(s)&&regex.test(s))return s;
        }
      }
    }
  }catch{}
  return null;
}
