// Passive URL signatures: CSP prevents fetching these URLs.
// Invalid hostnames are kept when their literal string matches a rule.
const splitPattern = s => String(s).split('\\;')[0];
const invalid = s => !s || s.length>700 || /[\x00-\x20<>"']/g.test(s) || /^(?:javascript|data|blob|file):/i.test(s);
const unique = array=>[...new Set(array)];
function candidates(value,hostname) {
  const v=value.replace(/^\/+/,'');
  return unique([
    value, value.startsWith('//')?'https:'+value:null,
    /^https?:\/\//i.test(value)?value:null,
    'https://'+v,
    'https://'+hostname+'/'+v,
    '/'+v
  ].filter(x=>x!=null&&!invalid(x)));
}
function matches(expr, attr, hostname) {
  const url = attr.startsWith('/')?'https://'+hostname+attr:attr;
  try {const re=new RegExp(expr,'i');return re.test(attr)||re.test(url);}catch{return false;}
}
export function makePassiveUrlCandidates(raw,witness,hostname='wappalyzer-technologies.pages.dev') {
  if(typeof raw!=='string'||!raw)return [];
  const expr=splitPattern(raw), v=witness(raw);
  if(!v)return [];
  const match=candidates(v,hostname).filter(c=>matches(expr,c,hostname));
  const old=match.find(c=>/^https?:\/\//.test(c));
  const relative=match.find(c=>c.startsWith('/'));
  return unique([old,relative,match[0]].filter(Boolean)).slice(0,2);
}
