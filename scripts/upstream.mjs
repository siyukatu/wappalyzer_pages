// Fetch Wappalyzer's current main branch in one upstream request.
// Extract every technologies/*.json from the public tar.gz. No GitHub API rate limit.
import { gunzipSync } from 'node:zlib';
const ARCHIVE='https://codeload.github.com/HTTPArchive/wappalyzer/tar.gz/refs/heads/main';
function nul(bytes){const i=bytes.indexOf(0);return (i<0?bytes:bytes.subarray(0,i)).toString('utf8');}
function parseArchive(gzip) {
  const tar=gunzipSync(gzip,{maxOutputLength:400*1024*1024});
  let offset=0;
  const sources=new Map();
  const extras=Object.create(null);
  while(offset+512<=tar.length) {
    const header=tar.subarray(offset,offset+512);
    if(header.every(b=>b===0))break;
    const name=nul(header.subarray(0,100));
    const prefix=nul(header.subarray(345,500));
    const path=prefix?prefix+'/'+name:name;
    const size=Number.parseInt(nul(header.subarray(124,136)).trim()||'0',8);
    const type=String.fromCharCode(header[156]);
    if(!Number.isSafeInteger(size)||size<0||offset+512+size>tar.length)throw new Error('Invalid upstream tar entry');
    const match=/^[^/]+\/src\/technologies\/([^/]+\.json)$/.exec(path);
    if (/^[^/]+\/src\/(?:categories\.json|js\/wappalyzer\.js)$/.test(path) && size<2000000) {
      extras[path.endsWith('categories.json')?'categories':'engine']=tar.subarray(offset+512,offset+512+size).toString('utf8');
    }
    if(match && (type==='0'||type==='\0') && size<10*1024*1024) {
      const key=match[1];
      if(sources.has(key))throw new Error('Duplicate upstream rules file: '+key);
      const value=JSON.parse(tar.subarray(offset+512,offset+512+size).toString('utf8'));
      if(value==null||typeof value!=='object'||Array.isArray(value))throw new Error('Invalid technology rule file: '+key);
      sources.set(key,value);
    }
    offset+=512+Math.ceil(size/512)*512;
  }
  const names=[...sources.keys()].sort();
  if(names.length<20)throw new Error('Too few technology JSON files in upstream archive: '+names.length);
  const technologies=Object.create(null);
  for(const filename of names)for(const [name,definition] of Object.entries(sources.get(filename))) {
    if(Object.hasOwn(technologies,name))throw new Error('Duplicate technology: '+name);
    Object.defineProperty(technologies,name,{value:definition,writable:true,enumerable:true,configurable:true});
  }
  return {files:names,technologies,extras};
}
export async function fetchTechnologyRules() {
  const response=await fetch(ARCHIVE,{headers:{'User-Agent':'wappalyzer-pages-builder','Accept':'application/gzip'},signal:AbortSignal.timeout(120000)});
  if(!response.ok)throw new Error('Upstream archive failed: HTTP '+response.status);
  const data=Buffer.from(await response.arrayBuffer());
  if(data.length>80*1024*1024)throw new Error('Upstream archive too large');
  return {...parseArchive(data),downloadBytes:data.length};
}
