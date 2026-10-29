// Compile all Wappalyzer js patterns into one prefix-sharing tree.
// No external libraries or runtime fetches. Values are synthetic.
const forbidden = new Set(['__proto__','prototype','constructor']);
const protectedGlobals = new Set([
  'window','document','self','top','parent','frames','location','navigator',
  'history','origin','localStorage','sessionStorage','indexedDB','fetch',
  'XMLHttpRequest','Object','Array','String','Number','Boolean','Function',
  'Promise','Math','JSON','Reflect','Symbol','Proxy','console','performance',
  'eval','alert','open','close','name','caches','crypto','customElements',
  'screen','Storage','WebSocket','EventSource','HTMLElement','HTMLDocument'
]);
function rules(value) { return Array.isArray(value) ? value : value == null ? [] : [value]; }
function normalize(name) {
  if (typeof name !== 'string') return null;
  name = name.replace(/^(?:window|globalThis)\./,'');
  if (!/^[a-z_$][\w$]*(?:\.[a-z_$][\w$]*){0,12}$/i.test(name)) return null;
  const bits = name.split('.');
  if (protectedGlobals.has(bits[0]) || bits.some(x=>forbidden.has(x))) return null;
  return bits;
}
const safeJSON = value => JSON.stringify(value).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');

export function compileGlobals(technologies, witness) {
  const paths = new Map();
  let inputPatterns=0;
  for (const technology of Object.values(technologies)) {
    const js = technology?.js;
    if (!js || typeof js !== 'object' || Array.isArray(js)) continue;
    for (const [path, entry] of Object.entries(js)) {
      const bits = normalize(path);
      if (!bits) continue;
      const key = bits.join('.');
      if (!paths.has(key)) paths.set(key, {bits, rules:[]});
      for (const v of rules(entry)) {
        paths.get(key).rules.push(v);
        inputPatterns++;
      }
    }
  }

  // The empty key stores the candidate value. Property path components can
  // never be empty, so this is a collision-free leaf marker.
  const tree = Object.create(null);
  let withWitness=0, validated=0;
  for (const {bits, rules:patterns} of [...paths.values()].sort((a,b)=>a.bits.length-b.bits.length || a.bits.join('.').localeCompare(b.bits.join('.')))) {
    const values = [...new Set(patterns.filter(x=>typeof x==='string').map(witness).filter(x=>typeof x==='string' && x.length<=250))];
    let candidate = {};
    let max = 0;
    for (const val of values) {
      let hits=0;
      for (const p of patterns) {
        if (typeof p!=='string' || !p) continue;
        try { if(new RegExp(p.split('\\;')[0],'i').test(val)) hits++; } catch {}
      }
      if (hits>max) { candidate=val; max=hits; }
    }
    if (max) { withWitness++; validated+=max; }
    let node=tree;
    for (const part of bits) node=node[part] ||= Object.create(null);
    node['']=candidate;
  }

  // Concise recursive hydration; one runtime loop, shared prefixes, no
  // per-path try/catch boilerplate or duplicated global definitions.
  const source = '(function(){const t='+safeJSON(tree)+
  ';function w(o,t){for(const k in t){try{const n=t[k],v=n[""];let x=o[k];const children=Object.keys(n).length-(Object.hasOwn(n,"")?1:0);'+
  'if(x==null){x=children&&typeof v==="string"?new String(v):children?{}:v===undefined?{}:v;o[k]=x;}'+
  'if(children&&(typeof x==="object"||typeof x==="function"))w(x,n)}catch{}}}w(globalThis,t)})();';
  return {source,stats:{globalPaths:paths.size,globalPatterns:inputPatterns,globalWitnesses:withWitness,globalPatternMatches:validated,globalTreeBytes:Buffer.byteLength(safeJSON(tree)),globalScriptBytes:Buffer.byteLength(source)}};
}
