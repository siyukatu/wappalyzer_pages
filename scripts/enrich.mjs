import { optimizeSharedHeader, augmentBeforeAnchoredSuffix } from './header-optimizer.mjs';
// Additional static-only fingerprint channels for Cloudflare Pages.
// Signatures are synthetic and must NEVER be interpreted as installed software.
export const SKIP_HEADERS = new Set([
  'content-security-policy','content-security-policy-report-only',
  'content-type','content-length','content-encoding','transfer-encoding',
  'cache-control','etag','last-modified','vary','location','date',
  'connection','keep-alive','set-cookie','access-control-allow-origin',
  'access-control-allow-credentials','access-control-allow-methods',
  'access-control-allow-headers','strict-transport-security',
  'x-frame-options','x-content-type-options','x-robots-tag','referrer-policy',
  'permissions-policy','clear-site-data','www-authenticate','refresh',
  'report-to','nel','link','content-disposition'
]);
const values = (v) => Array.isArray(v) ? v : v == null ? [] : [v];
const entries = (v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.entries(v) : [];
const escaped = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const plain = (v) => typeof v === 'string' && /^[\x20-\x7e]{1,250}$/.test(v) && !v.includes('<!--') && !v.includes('-->');
const prohibitedGlobal = new Set([
  'window','document','self','top','parent','frames','location','navigator',
  'history','origin','localStorage','sessionStorage','indexedDB','fetch',
  'XMLHttpRequest','Object','Array','String','Number','Boolean','Function',
  'Promise','Math','JSON','Reflect','Symbol','Proxy','console','performance',
  'eval','alert','open','close','name','caches','crypto','customElements',
  'screen','Storage','WebSocket','EventSource','HTMLElement','HTMLDocument'
]);
function selectorMarkup(raw) {
  if (typeof raw !== 'string' || raw.length > 250) return null;
  // One compound selector. Skip combinators and pseudo selectors rather
  // than claim matches for complex DOM relationships we cannot satisfy.
  const s = raw.trim();
  // Simple descendant / child chains are useful for many Wappalyzer DOM rules.
  // Keep only relationship markup that can be produced without remote code.
  if(!/[~+:]/.test(s) && /[\s>]/.test(s)) {
    const pieces=s.replace(/\s*>\s*/g,' ').split(/\s+(?![^\[]*\])/).filter(Boolean);
    if(pieces.length>1 && pieces.length<=5) {
      let nested='';
      for(const part of pieces.reverse()) {
        const markup=selectorMarkup(part);
        if(!markup || !/<\/[a-z][\w-]*>$/i.test(markup)) {nested='';break;}
        nested=markup.replace(/(<\/[a-z][\w-]*>)$/i,nested+'$1');
      }
      if(nested)return nested;
    }
  }
  if (/[>:~+]/.test(s) || /\s(?![^\[]*\])/.test(s)) return null;
  const tag = s.match(/^[a-z][a-z0-9-]*/i)?.[0] || 'div';
  if (['html','body','head','meta','title','base'].includes(tag.toLowerCase())) return null;
  const ids = [...s.matchAll(/#([a-z_][\w-]*)/ig)].map(m=>m[1]);
  const classes = [...s.matchAll(/\.([a-z_][\w-]*)/ig)].map(m=>m[1]);
  const attrs = [];
  const re = /\[([a-z_:][\w:.-]*)(?:([*^$|~]?=)\s*(['"]?)([^"'\\\]]*)\3)?\]/ig;
  for (const m of s.matchAll(re)) {
    const key = m[1].toLowerCase();
    if (key.startsWith('on') || ['srcdoc','integrity','nonce'].includes(key)) continue;
    // Attribute selectors are represented by their matchable substrings.
    const value = m[4] || 'fingerprint';
    if (!plain(value)) continue;
    attrs.push([m[1], m[2] === '$=' ? 'fp-' + value : m[2] === '^=' ? value + '-fp' : value]);
  }
  if (ids.length) attrs.push(['id',ids[0]]);
  if (classes.length) attrs.push(['class',classes.join(' ')]);
  const as = attrs.slice(0,8).map(([k,v]) => ' ' + k + '="' + escaped(v) + '"').join('');
  const voids = new Set(['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']);
  const safeTag = /^[a-z][a-z0-9-]{0,35}$/i.test(tag) ? tag : 'div';
  return voids.has(safeTag) ? '<' + safeTag + as + '>' : '<' + safeTag + as + '></' + safeTag + '>';
}
function selectHeaders(all, witness, missingNames = new Set(), urgentNames = new Set(), cap = 28000) {
  const patterns = new Map();
  for (const [techName, tech] of Object.entries(all)) {
    for (const [name, raw] of entries(tech?.headers)) {
      const lower = name.toLowerCase();
      if (!/^[a-z][a-z0-9-]{0,60}$/i.test(name) || SKIP_HEADERS.has(lower) ||
          lower.startsWith('cf-') || lower.startsWith('access-control-')) continue;
      for (const p of values(raw)) {
        if (typeof p !== 'string' || p.length > 700) continue;
        const v = typeof p === 'string' && p.split('\\;')[0] === '' ? '1' : witness(p);
        if (!plain(v) || v.length > 250 || !/^[\x20-\x7e]+$/.test(v)) continue;
        if (!patterns.has(lower)) patterns.set(lower, { name, rules: [], missing: new Set() });
        patterns.get(lower).rules.push({ regexp: p.split('\\;')[0], value: v, techName });
        if (missingNames.has(techName)) patterns.get(lower).missing.add(techName);
      }
    }
  }
  const candidates = [];
  let sharedHeaderDiagnostics = null;
  let viaHeaderDiagnostics = null;
  for (const {name, rules, missing} of patterns.values()) {
    const regexes = rules.map(({regexp,techName})=>{try{return {regex:new RegExp(regexp,'i'),weight:urgentNames.has(techName)?6:missingNames.has(techName)?3:1}}catch{return null}}).filter(Boolean);
    if (!regexes.length) continue;
    let best = '';
    let score = 0;
    // Find a high-coverage single value, then greedily append values only
    // when appending increases the number of independently matching patterns.
    const distinct = [...new Set(rules.map(r => r.value))].sort((a,b) => a.length-b.length).slice(0,250);
    const coverage = v => regexes.reduce((n,item) => n + (item.regex.test(v)?item.weight:0),0);
    for (const v of distinct) {
      const count = coverage(v);
      if (count > score || (count === score && (!best || v.length < best.length))) { best = v; score = count; }
    }
    for (let round=0; round<40; round++) {
      let next = best, count = score;
      for (const v of distinct) {
        if (best.includes(v)) continue;
        const possible = best + ', ' + v;
        if (possible.length > 1700) continue;
        const hits = coverage(possible);
        if (hits > count) { next = possible; count = hits; }
      }
      if (next === best) break;
      best = next; score = count;
    }
    if (name.toLowerCase()==='x-powered-by') {
      const improved=optimizeSharedHeader(
        rules.map(r=>({...r,weight:urgentNames.has(r.techName)?6:missingNames.has(r.techName)?3:1})),best);
      sharedHeaderDiagnostics={before:improved.baseline,after:improved.matched,
        extraTechnologies:Math.max(0,improved.matched-improved.baseline),
        techNames:improved.names};
      if(improved.matched>improved.baseline) {
        best=improved.value;
        score=coverage(best);
      }
    }
    if(name.toLowerCase()==='via') {
      const improved=augmentBeforeAnchoredSuffix(rules,best);
      viaHeaderDiagnostics={before:improved.before,after:improved.after,added:improved.added};
      if(improved.after>improved.before) {
        best=improved.value;
        score=coverage(best);
      }
    }
    if (best) candidates.push({name, best, score, missingCount:missing.size, size: name.length+best.length+4});
  }
  // Valuable uncommon header fields are retained as long as the practical
  // response-size budget holds. A huge response can fail at upstream proxies.
  candidates.sort((a,b) => (b.score + b.missingCount*3)/b.size - (a.score + a.missingCount*3)/a.size || a.name.localeCompare(b.name));
  const lines = [];
  let total = 0, score = 0;
  for (const c of candidates) {
    if (total + c.size > cap || c.size > 1950 || lines.length >= 650) continue;
    lines.push('  ' + c.name + ': ' + c.best);
    total += c.size;
    score += c.score;
  }
  return {lines, count:lines.length, approxMatches:score, bytes:total, sharedHeaderDiagnostics, viaHeaderDiagnostics};
}
export function generateExtras(all, witness, missingNames = new Set(), urgentNames = new Set(), preserveNames = new Set()) {
  const dom = new Set(), comments = new Set(), cookieValues = new Map(), cookieVariants = new Map(), js = new Map(), domProperties = new Map();
  let domRuleCount = 0, cookieRuleCount=0;
  for (const [techName, tech] of Object.entries(all)) {
    const dr = tech?.dom;
    const selectors = typeof dr === 'string' || Array.isArray(dr) ? values(dr) : Object.keys(dr || {});
    for (const sel of selectors) {
      domRuleCount++;
      // The extension tests own DOM element properties, which plain HTML
      // attributes cannot synthesize. Create safe own-property witnesses before
      // the extension's document_idle scan, using a DOMContentLoaded callback.
      const variants=dr && !Array.isArray(dr) && typeof dr==='object' ? values(dr[sel]) : [];
      for(const variant of variants) {
        if(!variant || typeof variant!=='object')continue;
        for(const [property,patterns] of entries(variant.properties)) {
          if(!/^[a-z_$][\w$-]{0,65}$/i.test(property) ||
             /^(?:on[a-z]+|__proto__|prototype|constructor|innerHTML|outerHTML|src|href|style|className|id|textContent)$/i.test(property))continue;
          for(const pattern of values(patterns)) {
            const val=typeof pattern==='string' && pattern.split('\\;')[0]==='' ? '1' : witness(pattern);
            if(typeof val!=='string'||val.length>180||/[\r\n]/.test(val))continue;
            const key=JSON.stringify([sel,property,val]);
            if(domProperties.size<1200)domProperties.set(key,[sel,property,val]);
          }
        }
      }
      for (const piece of String(sel).split(/,(?![^\[]*\])/)) {
        const markup = selectorMarkup(piece);
        if (markup) dom.add(markup);
        // Object-form DOM rules frequently impose a regex on attribute
        // contents, beyond the selector itself. Add a separate valid witness
        // element, leaving the selector-derived element in place as a fallback.
        const detail=dr && !Array.isArray(dr) && typeof dr==='object' ? dr[sel] : null;
        if (!markup || !detail || typeof detail !== 'object') continue;
        let enhanced=markup;
        for (const [attr, rule] of entries(detail.attributes)) {
          if(!/^[a-z][\w:-]*$/i.test(attr) || /^on/i.test(attr) || attr==='srcdoc')continue;
          const pattern=values(rule).find(x=>typeof x==='string');
          const val=typeof pattern==='string' && pattern!=='' ? witness(pattern) : '1';
          if(typeof val!=='string' || val.length>200 || /[\r\n"'<>]/.test(val))continue;
          const existing=new RegExp('\\s'+attr+'="([^"]*)"','i').exec(enhanced);
          if(existing) {
            const old=existing[1].replace(/&amp;/g,'&');
            const candidates=[val,old+val,val+old,old+'/'+val,val+'/'+old];
            const base=piece.match(new RegExp('\\['+attr+'\\*?=[\'"]?([^\'"\\]]+)','i'));
            const valid=candidates.find(c=>{
              try{return new RegExp(pattern.split('\\;')[0],'i').test(c)&&(!base || c.includes(base[1]));}catch{return false;}
            });
            if(!valid)continue;
            enhanced=enhanced.replace(existing[0],' '+attr+'="'+escaped(valid)+'"');
          }else enhanced=enhanced.replace(/(\/?>)$/,' '+attr+'="'+escaped(val)+'"$1');
        }
        if(enhanced!==markup)dom.add(enhanced);
        for (const rule of values(detail.text)) {
          const content = rule === '' ? '' : witness(rule);
          if(content === null || content.length>200 || /[\r\n]/.test(content)) continue;
          const m=/^<([a-z][\w-]*)\b[^>]*>([\s\S]*)<\/\1>$/i.exec(enhanced);
          if(!m)continue;
          const end='</'+m[1]+'>';
          dom.add(enhanced.slice(0,-end.length)+escaped(content)+end);
        }
      }
    }
    for (const rule of values(tech?.html)) {
      const sample = witness(rule);
      if (typeof sample !== 'string' || sample.length > 180 || comments.size >= 8000) continue;
      // Preserve genuine source-comment signatures (for example RebelMouse).
      // Wrapping "<!-- ..." in a second comment would not serialize the
      // expected bytes; text-escaping it would also break the HTML rule.
      if (sample.startsWith('<!--') && !sample.includes('-->') &&
          !sample.slice(4).includes('<!--') && !/[<>\r\n]/.test(sample.slice(4))) {
        comments.add(sample + '-->');
      } else if (plain(sample)) {
        comments.add('<!--' + sample + '-->');
      }
    }
    for (const [name, raw] of entries(tech?.cookies)) {
      cookieRuleCount++;
      if (!/^[a-z0-9_!#$%&'*+.^|~-]{1,80}$/i.test(name)) continue;
      const sample = values(raw).map(witness).find(v => typeof v === 'string' && /^[a-z0-9_.-]{1,80}$/i.test(v)) || '1';
      // Give scarce first-party cookie slots to technologies that cannot be
      // detected through any other static Pages signal.
      const alternatives=['headers','meta','js','dom','scriptSrc','scripts','css',
        'html','text','url','xhr','robots','dns','probe','certIssuer'];
      const cookieOnly=alternatives.every(k=>{
        const v=tech?.[k];
        return v==null || (Array.isArray(v)&&v.length===0) ||
          (typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===0);
      });
      const priority = urgentNames.has(techName) ? 1300 : preserveNames.has(techName) ? 1200 : cookieOnly ? 900 : missingNames.has(techName) ? 10 : 0;
      const prior = cookieValues.get(name);
      if (!prior || priority>prior.priority) cookieValues.set(name,{value:sample,priority,cookieOnly});
      // Keep every valid alternative for the same cookie name. An opt-in
      // monotone value merger may satisfy several regexes in the same slot.
      for (const pattern of values(raw)) {
        if (typeof pattern!=='string' || pattern.length>300) continue;
        const expr=pattern.split('\\;')[0];
        try { const re=new RegExp(expr,'i');
          const candidate=expr==='' ? '1' : witness(pattern);
          if(typeof candidate==='string' && /^[a-z0-9_.-]{1,80}$/i.test(candidate) && re.test(candidate)) {
            if(!cookieVariants.has(name)) cookieVariants.set(name,[]);
            cookieVariants.get(name).push({re,candidate});
          }
        } catch {}
      }
    }

  }
  const orderedCookies=[...cookieValues].sort((a,b)=>b[1].priority-a[1].priority || a[0].localeCompare(b[0]));
  let cookieRegexMatchesBefore=0, cookieRegexMatchesAfter=0, mergedCookies=0;
  // Do not evict any of the 360 names. Preserve *every* regex matched by
  // the existing value; adopt combined ASCII values only for strict gains.
  for (const [name,record] of orderedCookies.slice(0,360)) {
    const rules=cookieVariants.get(name)||[];
    const matches=value=>rules.reduce((n,r)=>n+(r.re.test(value)?1:0),0);
    const baseline=record.value;
    let best=baseline, count=matches(baseline);
    cookieRegexMatchesBefore+=count;
    if (rules.length>1) for (const {candidate} of rules) {
      for (const v of [candidate,best+'-'+candidate,candidate+'-'+best,best+'_'+candidate,candidate+'_'+best]) {
        if(v.length>80 || !/^[a-z0-9_.-]+$/i.test(v) || v===best)continue;
        if (!rules.every(r=>!r.re.test(baseline)||r.re.test(v)))continue;
        const score=matches(v);
        if(score>count){best=v;count=score;}
      }
    }
    if(best!==baseline){record.value=best;mergedCookies++;}
    cookieRegexMatchesAfter+=count;
  }
  const chosenCookies=orderedCookies.slice(0,180);
  // CHIPS provides an independent top-level-site cookie partition in Chrome.
  // The browser probe independently confirmed 110 regular + 110 partitioned
  // cookies coexist and are visible to document.cookie on this origin.
  // Never replace existing 180 ordinary cookies with these extra candidates.
  // Trial: fill the last 15 CHIPS candidate slots while preserving all
  // 180 ordinary and the first 165 partitioned cookie witnesses.
  const partitionedCookies=orderedCookies.slice(180,360);
  const nativePreservedChosen=chosenCookies.filter(([,value])=>value.priority>=1200).length;
  const cookieOnlyChosen=chosenCookies.filter(([,value])=>value.cookieOnly).length;
  const cookieList=chosenCookies.reverse().map(([name,obj])=>[name,obj.value]);
  const partitionedList=partitionedCookies.reverse().map(([name,obj])=>[name,obj.value]);
  const cookieScript = 'for(const [name,value] of ' + JSON.stringify(cookieList) +
    '){try{document.cookie=name+"="+encodeURIComponent(value)+"; Path=/; SameSite=Lax; Secure";}catch{}}' +
    'for(const [name,value] of ' + JSON.stringify(partitionedList) +
    '){try{document.cookie=name+"="+encodeURIComponent(value)+"; Path=/; SameSite=None; Secure; Partitioned";}catch{}}';
  const propJSON=JSON.stringify([...domProperties.values()]).replace(/</g,'\\u003c');
  const propertyScript = 'if(typeof document.addEventListener==="function")document.addEventListener("DOMContentLoaded",()=>{for(const [selector,property,value] of '+propJSON+'){try{for(const element of document.querySelectorAll(selector)){Object.defineProperty(element,property,{value,writable:true,configurable:true})}}catch{}}});';
  const headers = selectHeaders(all,witness,missingNames,urgentNames);
  const body = [...dom].join('') + [...comments].join('');
  return {
    bootstrap: cookieScript + propertyScript,
    body, headers,
    stats: {additionalDom:dom.size, htmlComments:comments.size, syntheticDomProperties:domProperties.size, cookies:cookieList.length, partitionedCookies:partitionedList.length, cookieOnlyChosen, nativePreservedChosen, mergedCookies, cookieRegexMatchesBefore, cookieRegexMatchesAfter, upstreamDomSelectors:domRuleCount, upstreamCookieRules:cookieRuleCount,
      syntheticHeaderFields: headers.count, syntheticHeaderMatches:headers.approxMatches, syntheticHeaderBytes: headers.bytes,
      sharedHeaderDiagnostics:headers.sharedHeaderDiagnostics,
      viaHeaderDiagnostics:headers.viaHeaderDiagnostics}
  };
}
export function emitHeaders(hash, extras, styleHash, shards = []) {
  const csp = [
    "default-src 'none'", "script-src 'sha256-" + hash + "'",
    "script-src-attr 'none'", "style-src 'sha256-" + styleHash + "'", "style-src-attr 'none'", "img-src 'none'",
    "font-src 'none'", "connect-src 'none'", "frame-src 'none'",
    "child-src 'none'", "worker-src 'none'", "media-src 'none'",
    "manifest-src 'none'", "object-src 'none'", "form-action 'none'",
    "base-uri 'none'", "frame-ancestors 'self'"
  ].join('; ');
  const lines = [
    '/*',
    '  Content-Security-Policy: ' + csp,
    '  X-Frame-Options: SAMEORIGIN',
    '  X-Content-Type-Options: nosniff',
    '  Referrer-Policy: no-referrer',
    '  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    '  X-Robots-Tag: noindex, nofollow, noarchive',
    '  Cache-Control: public, max-age=0, must-revalidate',
    '/',
    ...extras.headers.lines,
    '/index.html',
    ...extras.headers.lines,
    ...shards.flatMap(shard => ['/' + shard.path.replace(/\.html$/, ''), ...shard.headers])
  ];
  if (lines.some(line=>line.length>2000)) throw new Error('_headers line exceeds Cloudflare Pages limit');
  return lines.join('\n') + '\n';
}
