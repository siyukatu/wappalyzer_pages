#!/usr/bin/env node
// Compare a fresh Wappalyzer CSV export against the checked-in baseline.
// Wappalyzer exports a single row with semicolon-separated names per category.
// Usage: node scripts/compare.mjs /path/to/new-export.csv
import { readFile } from 'node:fs/promises';
const normalize = value => String(value).normalize('NFKC').trim().toLocaleLowerCase('en');
function parseCSV(text) {
  const result=[];let row=[],value='',quoted=false;
  for(let i=0;i<text.length;i++) {
    const c=text[i];
    if(quoted) {
      if(c==='"'&&text[i+1]==='"'){value+='"';i++;}
      else if(c==='"')quoted=false;
      else value+=c;
    }else if(c==='"')quoted=true;
    else if(c===','){row.push(value);value='';}
    else if(c==='\n'){row.push(value.replace(/\r$/,''));result.push(row);row=[];value='';}
    else value+=c;
  }
  if(row.length||value) {row.push(value);result.push(row);}
  return result;
}
export function extractDetections(csv) {
  const rows=parseCSV(csv.replace(/^\uFEFF/,''));
  if(rows.length<2 || rows[0][0]!=='URL')throw new Error('Expected a Wappalyzer CSV with URL header and data rows');
  const known=new Map();
  const headers=rows[0];
  for(const row of rows.slice(1)) {
    for(let i=1;i<headers.length;i++) {
      if(['電話番号','メールアドレス','Email','Phone'].includes(headers[i]))continue;
      const cell=row[i]||'';
      for(const name of cell.split(/\s+;\s+/)) {
        const n=name.trim();
        if(n)known.set(normalize(n),n);
      }
    }
  }
  return known;
}
const source=process.argv[2];
if(source) {
  const [original,csv] = await Promise.all([
    readFile('data/detected-baseline.json','utf8').then(JSON.parse),
    readFile(source,'utf8')
  ]);
  const before=new Map(original.detected.map(n=>[normalize(n),n]));
  const after=extractDetections(csv);
  const gained=[...after].filter(([n])=>!before.has(n)).map(([,v])=>v).sort();
  const lost=[...before].filter(([n])=>!after.has(n)).map(([,v])=>v).sort();
  const result={
    baseline:before.size, current:after.size, netChange:after.size-before.size,
    gainedCount:gained.length, lostCount:lost.length,gained,lost
  };
  console.log(JSON.stringify(result,null,2));
}
