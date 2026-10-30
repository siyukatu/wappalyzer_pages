// Distribute mutually incompatible synthetic header witnesses over static
// same-origin HTML documents. These are an experiment: native Wappalyzer may
// ignore iframe response headers. Never treat predicted matches as detections.
import { SKIP_HEADERS } from './enrich.mjs';

const SHARD_LIMIT = 3;
const FIELDS_PER_SHARD = 90;
const BYTES_PER_SHARD = 8500;
const entries = v => v && typeof v === 'object' && !Array.isArray(v) ? Object.entries(v) : [];
const values = v => Array.isArray(v) ? v : v == null ? [] : [v];
const safeValue = v => typeof v === 'string' && /^[\x20-\x7e]{1,250}$/.test(v) &&
  !v.includes('<!--') && !v.includes('-->');
const safeName = name => /^[a-z][a-z0-9-]{0,60}$/i.test(name) &&
  !SKIP_HEADERS.has(name.toLowerCase()) &&
  !name.toLowerCase().startsWith('cf-') &&
  !name.toLowerCase().startsWith('access-control-');
const weight = (name, missing, urgent) => urgent.has(name) ? 6 : missing.has(name) ? 3 : 1;

export function generateHeaderShards(all, witness, baselineLines, missing = new Set(), urgent = new Set()) {
  const baseline = new Map(baselineLines.map(line => {
    const match = /^  ([a-z0-9-]+): (.*)$/i.exec(line);
    return match ? [match[1].toLowerCase(), match[2]] : null;
  }).filter(Boolean));
  const groups = new Map();
  for (const [techName, tech] of Object.entries(all)) {
    for (const [name, raw] of entries(tech?.headers)) {
      if (!safeName(name)) continue;
      const key = name.toLowerCase();
      if (!groups.has(key)) groups.set(key, {name, rules: [], witnesses: new Set()});
      const group = groups.get(key);
      for (const pattern of values(raw)) {
        if (typeof pattern !== 'string' || pattern.length > 700) continue;
        const source = pattern.split('\\;')[0];
        let regex;
        try { regex = new RegExp(source, 'i'); } catch { continue; }
        const value = source === '' ? '1' : witness(pattern);
        if (!safeValue(value) || !regex.test(value)) continue;
        group.rules.push({techName, regex});
        group.witnesses.add(value);
      }
    }
  }
  const covered = new Map();
  for (const [key, group] of groups) {
    const root = baseline.get(key);
    covered.set(key, new Set(root == null ? [] :
      group.rules.filter(rule => rule.regex.test(root)).map(rule => rule.techName)));
  }
  const shards = [];
  const novelNames = new Set();
  for (let index = 0; index < SHARD_LIMIT; index++) {
    const picks = [];
    for (const [key, group] of groups) {
      const seen = covered.get(key);
      let best = null;
      for (const value of group.witnesses) {
        const gained = new Set();
        for (const rule of group.rules) {
          if (!seen.has(rule.techName) && rule.regex.test(value)) gained.add(rule.techName);
        }
        if (!gained.size) continue;
        const score = [...gained].reduce((n, name) => n + weight(name, missing, urgent), 0);
        if (!best || score > best.score || score === best.score && value.length < best.value.length)
          best = {key, name:group.name, value, gained, score};
      }
      if (best) picks.push(best);
    }
    picks.sort((a,b) => b.score-a.score || a.value.length-b.value.length || a.key.localeCompare(b.key));
    const headers = [];
    let bytes = 0;
    for (const pick of picks) {
      const line = '  ' + pick.name + ': ' + pick.value;
      const size = Buffer.byteLength(line) + 1;
      if (headers.length >= FIELDS_PER_SHARD || bytes + size > BYTES_PER_SHARD || line.length > 2000) continue;
      headers.push(line);
      bytes += size;
      for (const name of pick.gained) {covered.get(pick.key).add(name); novelNames.add(name);}
    }
    if (!headers.length) break;
    const path = 'header-shards/' + String(index+1).padStart(2,'0') + '.html';
    const html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow,noarchive"><title>Synthetic header shard</title></head><body></body></html>';
    shards.push({path, html, headers, bytes});
  }
  return {shards, stats:{
    count:shards.length, fields:shards.map(s=>s.headers.length),
    bytes:shards.map(s=>s.bytes),
    estimatedNovelHeaderRuleNames:novelNames.size,
    note:'Estimated per-header regex coverage only; native iframe aggregation must be measured.'
  }};
}
