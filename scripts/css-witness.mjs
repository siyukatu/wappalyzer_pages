// Add passive CSS feature markers into the same CSP-hashed inline style.
export function cssFingerprints(all,witness) {
  const entries=new Set();
  for(const tech of Object.values(all)) {
    const rules=Array.isArray(tech?.css)?tech.css:tech?.css==null?[]:[tech.css];
    for(const raw of rules) {
      if(typeof raw!=='string' || !raw || raw.length>300)continue;
      const sample=witness(raw);
      if(!sample||sample.length>160||/[\x00-\x1f{};<>]/.test(sample))continue;
      let css;
      if(/^--[a-z0-9_-]+$/i.test(sample))css=':root{'+sample+':0}';
      else if(/^[.#][\w.-]+(?:\s+[.#][\w.-]+)*$/.test(sample))css=sample+'{--wfp:1}';
      else if(/^[a-z][a-z0-9-]*$/i.test(sample))css=sample+'{--wfp:1}';
      else continue;
      let re;
      try{re=new RegExp(raw.split('\\;')[0],'i')}catch{continue}
      if(re.test(css))entries.add(css);
    }
  }
  return {css:[...entries].join(''),rules:entries.size};
}
