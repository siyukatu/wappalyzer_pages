#!/usr/bin/env node
// Use the same upstream rule snapshot and original Wappalyzer matching engine.
// Nothing from this diagnostic is shipped to Cloudflare Pages.
import { mkdir, writeFile } from 'node:fs/promises';
import { fetchTechnologyRules } from './upstream.mjs';
import { fetchStoreRules } from './store-rules.mjs';

const out=process.env.DIAGNOSTIC_DIR||'.selfcheck';
const [{files,technologies,extras,source,downloadBytes}, archived]=await Promise.all([
  fetchStoreRules(),fetchTechnologyRules()
]);
if(!archived.extras.engine)throw new Error('Original Wappalyzer engine missing from HTTPArchive');
const categoryJson=extras.categories||archived.extras.categories;
if(!categoryJson)throw new Error('No Wappalyzer category definitions found');
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
  writeFile(out+'/categories.json',categoryJson),
  writeFile(out+'/engine.cjs',archived.extras.engine),
  writeFile(out+'/rule-source.json',JSON.stringify(source)),
  writeFile(out+'/specs.json',JSON.stringify({js:[...js],dom}))
]);
console.log(JSON.stringify({snapshotRules:Object.keys(technologies).length,ruleFiles:files.length,jsPaths:js.size,domSelectors:dom.length,crxVersion:source.version,crxSha256:source.sha256,storeBytes:downloadBytes,engine:'HTTPArchive archived Wappalyzer core'}));
