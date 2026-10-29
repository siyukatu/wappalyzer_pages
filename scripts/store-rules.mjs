// Fetch the actual Chrome Web Store Wappalyzer CRX and read its embedded
// technologies/*.json. No third-party CRX mirror, npm dependency, or server-side
// extension execution is involved. Do not run the extension's bundled scripts.
import { inflateRawSync } from 'node:zlib';
import { createHash } from 'node:crypto';

export const EXTENSION_ID='gppongmhjkpfnbhagpmjfkannfbllamg';
const STORE='https://clients2.google.com/service/update2/crx';
const MAX_CRX=100*1024*1024;

function zipPayload(raw) {
  if(raw.subarray(0,2).toString()==='PK')return {zip:raw,crxFormat:'zip'};
  if(raw.subarray(0,4).toString()!=='Cr24')throw Error('Google update endpoint did not return a CRX or ZIP package');
  if(raw.length<16)throw Error('Truncated CRX header');
  const version=raw.readUInt32LE(4);
  let start;
  if(version===3)start=12+raw.readUInt32LE(8);
  else if(version===2)start=16+raw.readUInt32LE(8)+raw.readUInt32LE(12);
  else throw Error('Unsupported Chrome extension package format: CRX'+version);
  if(start<=12||start>=raw.length || raw.toString('binary',start,start+2)!=='PK')throw Error('Invalid CRX ZIP payload offset');
  return {zip:raw.subarray(start),crxFormat:'crx'+version};
}
function zipEntries(zip) {
  // ZIP end-of-central-directory record is in the final 64 KiB.
  let tail=-1;
  for(let i=zip.length-22;i>=Math.max(0,zip.length-65557);i--){
    if(zip.readUInt32LE(i)===0x06054b50){tail=i;break}
  }
  if(tail<0)throw Error('ZIP central-directory trailer not found');
  const total=zip.readUInt16LE(tail+10);
  const offset=zip.readUInt32LE(tail+16);
  if(total===0xffff||offset===0xffffffff)throw Error('ZIP64 packages are not supported');
  let cursor=offset;
  const entries=new Map();
  for(let i=0;i<total;i++){
    if(cursor+46>zip.length||zip.readUInt32LE(cursor)!==0x02014b50)throw Error('Invalid ZIP central directory');
    const flags=zip.readUInt16LE(cursor+8);
    const method=zip.readUInt16LE(cursor+10);
    const compressed=zip.readUInt32LE(cursor+20);
    const uncompressed=zip.readUInt32LE(cursor+24);
    const namelen=zip.readUInt16LE(cursor+28);
    const extralen=zip.readUInt16LE(cursor+30);
    const commentlen=zip.readUInt16LE(cursor+32);
    const local=zip.readUInt32LE(cursor+42);
    const end=cursor+46+namelen+extralen+commentlen;
    if(end>zip.length)throw Error('Truncated ZIP central record');
    const name=zip.subarray(cursor+46,cursor+46+namelen).toString('utf8');
    cursor=end;
    if((flags&1)!==0 || ![0,8].includes(method))continue;
    if(uncompressed>12*1024*1024||compressed>12*1024*1024)continue;
    if(name.includes('..') || name.startsWith('/') || name.endsWith('/'))continue;
    const key=/^(?:[^/]+\/)*technologies\/([^/]+\.json)$/.exec(name);
    const metadata=/^(?:[^/]+\/)*(manifest\.json|categories\.json)$/.exec(name);
    if(!key&&!metadata)continue;
    if(local+30>zip.length||zip.readUInt32LE(local)!==0x04034b50)throw Error('Corrupt ZIP file header');
    const data=local+30+zip.readUInt16LE(local+26)+zip.readUInt16LE(local+28);
    if(data+compressed>zip.length)throw Error('ZIP entry exceeds package bounds');
    const compressedData=zip.subarray(data,data+compressed);
    const bytes=method===0?compressedData:inflateRawSync(compressedData,{maxOutputLength:12*1024*1024});
    if(bytes.length!==uncompressed)throw Error('Invalid decompressed ZIP entry length: '+name);
    entries.set(name,bytes);
  }
  return entries;
}
async function downloadPackage() {
  const version=process.env.CRX_CHROME_VERSION||'156.0.0.0';
  const url=new URL(STORE);
  url.searchParams.set('response','redirect');
  url.searchParams.set('prodversion',version);
  url.searchParams.set('acceptformat','crx2,crx3');
  url.searchParams.set('x','id='+EXTENSION_ID+'&uc');
  const response=await fetch(url,{redirect:'follow',headers:{
    'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/'+version+' Safari/537.36',
    'Accept':'*/*'
  },signal:AbortSignal.timeout(120000)});
  if(!response.ok)throw Error('Chrome Web Store CRX download failed: HTTP '+response.status);
  const buffer=Buffer.from(await response.arrayBuffer());
  if(buffer.length===0||buffer.length>MAX_CRX)throw Error('Unexpected Chrome Web Store CRX size');
  return buffer;
}
export async function fetchStoreRules() {
  const raw=await downloadPackage();
  const {zip,crxFormat}=zipPayload(raw);
  const entries=zipEntries(zip);
  const json=new Map();
  let manifest=null, categories=null;
  const all=Object.create(null);
  for(const [path,bytes] of entries){
    if(/(?:^|\/)manifest\.json$/.test(path) && !manifest)manifest=JSON.parse(bytes.toString('utf8'));
    if(/(?:^|\/)categories\.json$/.test(path) && !categories)categories=bytes.toString('utf8');
    const m=/(?:^|\/)technologies\/([^/]+\.json)$/.exec(path);
    if(!m)continue;
    const decoded=JSON.parse(bytes.toString('utf8'));
    if(!decoded||typeof decoded!=='object'||Array.isArray(decoded))throw Error('Invalid rule JSON in extension: '+path);
    if(json.has(m[1]))throw Error('Duplicate technology file in CRX: '+m[1]);
    json.set(m[1],decoded);
  }
  if(!manifest?.version)throw Error('Chrome Web Store CRX manifest version is absent');
  if(json.size<20)throw Error('Expected at least 20 bundled technologies JSON files in Wappalyzer CRX, found '+json.size);
  for(const file of [...json.keys()].sort()){
    for(const [name,technology] of Object.entries(json.get(file))){
      if(Object.hasOwn(all,name))throw Error('Duplicate bundled technology: '+name);
      Object.defineProperty(all,name,{value:technology,enumerable:true,configurable:true});
    }
  }
  if(Object.keys(all).length<1000)throw Error('Bundled Wappalyzer technology catalog is unexpectedly small');
  return {
    files:[...json.keys()].sort(),
    technologies:all,
    extras:{categories},
    source:{
      type:'chrome-web-store-crx',
      extensionId:EXTENSION_ID,
      version:manifest.version,
      crxFormat,
      sizeBytes:raw.length,
      sha256:createHash('sha256').update(raw).digest('hex'),
      technologyFiles:json.size,
      technologies:Object.keys(all).length,
      storeUrl:'https://chromewebstore.google.com/detail/gppongmhjkpfnbhagpmjfkannfbllamg'
    },
    downloadBytes:raw.length
  };
}
