#!/usr/bin/env node
// Use the exact matching engine and fingerprint snapshot extracted from the same Web Store CRX.
// Nothing from this diagnostic is shipped to Cloudflare Pages.
import { mkdir, writeFile } from 'node:fs/promises';
import { fetchStoreRules } from './store-rules.mjs';

const out=process.env.DIAGNOSTIC_DIR||'.selfcheck';
const {files,technologies,extras,source,downloadBytes}=await fetchStoreRules();
if(!extras.engine)throw new Error('Matching engine is absent from downloaded CRX');
if(!extras.categories)throw new Error('Categories are absent from downloaded CRX');
const dom=[];
const js=new Set();
for(const [name,tech] of Object.entries(technologies)){
  const globals=tech.js&&typeof tech.js==='object'&&!Array.isArray(tech.js)?Object.keys(tech.js):[];
  for(const p of globals)js.add(p);
  const defs=typeof tech.dom==='string'||Array.isArray(tech.dom)
    ?Object.fromEntries((Array.isArray(tech.dom)?tech.dom:[tech.dom]).map(x=>[x,{}]))
    :tech.dom||{};
  for(const [selector,detail] of Object.entries(defs)){
    const object=detail&&typeof detail==='object'&&!Array.isArray(detail)?detail:{};
    dom.push({
      name,selector,
      text:object.text!==undefined,
      attributes:Object.keys(object.attributes||{}),
      properties:Object.keys(object.properties||{})
    });
  }
}
await mkdir(out,{recursive:true});
await Promise.all([
  writeFile(out+'/rules.json',JSON.stringify(technologies)),
  writeFile(out+'/categories.json',extras.categories),
  writeFile(out+'/engine.cjs',extras.engine),
  writeFile(out+'/rule-source.json',JSON.stringify(source)),
  writeFile(out+'/specs.json',JSON.stringify({js:[...js],dom}))
]);
console.log(JSON.stringify({snapshotRules:Object.keys(technologies).length,ruleFiles:files.length,jsPaths:js.size,domSelectors:dom.length,crxVersion:source.version,crxSha256:source.sha256,storeBytes:downloadBytes,engine:'Exact Chrome Web Store Wappalyzer CRX js/wappalyzer.js'}));
