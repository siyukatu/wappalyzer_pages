// Translate simple Wappalyzer html/body selectors into attributes on the real
// document roots, rather than synthesizing ineffective nested <body> elements.
const escape = v=>String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
function splitSelectors(input){
  const result=[];let start=0,depth=0,quote='';
  for(let i=0;i<input.length;i++){
    const c=input[i];
    if(quote){if(c===quote)quote='';continue;}
    if(c==='"'||c==="'"){quote=c;continue;}
    if(c==='[')depth++;
    else if(c===']')depth=Math.max(0,depth-1);
    else if(c===','&&depth===0){result.push(input.slice(start,i).trim());start=i+1;}
  }
  result.push(input.slice(start).trim());return result;
}
const blocked=new Set(['src','srcdoc','nonce','integrity','action','background','manifest','onload','onclick','onerror','contenteditable','hidden','style-on']);
export function rootAttributes(rules){
  const roots={html:{classes:new Set(),attributes:new Map(),ids:new Set()},body:{classes:new Set(),attributes:new Map(),ids:new Set()}};
  let inspected=0,usable=0;
  for(const tech of Object.values(rules)){
    const list=typeof tech?.dom==='string'?[tech.dom]:Array.isArray(tech?.dom)?tech.dom: tech?.dom&&typeof tech.dom==='object'?Object.keys(tech.dom):[];
    for(const raw of list){if(typeof raw!=='string')continue;
      for(const part of splitSelectors(raw)){
        const m=/^(html|body)((?:[.#][a-z_][\w-]*|\[[^\]]{1,180}\])*)$/i.exec(part);
        if(!m||!m[2])continue;
        inspected++;
        const root=roots[m[1].toLowerCase()];const suffix=m[2];
        const tokens=suffix.match(/(?:[.#][a-z_][\w-]*|\[[^\]]{1,180}\])/ig)||[];
        if(tokens.join('')!==suffix)continue;
        let okay=false;
        for(const token of tokens){
          if(token[0]==='.') {root.classes.add(token.slice(1));okay=true;continue;}
          if(token[0]==='#') {root.ids.add(token.slice(1));okay=true;continue;}
          const match=/^\[([a-z_:][\w:.-]*)(?:\s*([*^$|~]?=)\s*(['"]?)([^'"\]]*)\3)?\]$/i.exec(token);
          if(!match)continue;
          const key=match[1].toLowerCase();
          if(key.startsWith('on')||blocked.has(key)||key==='lang')continue;
          const op=match[2]||'';
          const val=match[4]??'';
          if(val.length>140||/[\r\n<>]/.test(val))continue;
          if(key==='class'){
            if(val)root.classes.add(val);
            okay=true;continue;
          }
          if(key==='id'){
            if(val)root.ids.add(val);
            okay=true;continue;
          }
          const values=root.attributes.get(key)||[];
          values.push({op,val});root.attributes.set(key,values);
          okay=true;
        }
        if(okay)usable++;
      }
    }
  }
  const attrs={};
  for(const [tag,root]of Object.entries(roots)){
    const pieces=[];
    if(root.classes.size)pieces.push('class="'+escape([...root.classes].join(' '))+'"');
    if(root.ids.size)pieces.push('id="'+escape([...root.ids][0])+'"');
    for(const [name,values] of root.attributes){
      if(name==='class'||name==='id')continue;
      const eq=values.find(x=>x.op==='=');
      const begins=values.filter(x=>x.op==='^=').map(x=>x.val);
      const ends=values.filter(x=>x.op==='$=').map(x=>x.val);
      const inside=values.filter(x=>x.op==='*='||x.op==='~='||x.op==='|=').map(x=>x.val);
      const value=eq?eq.val:(begins[0]||'')+(inside.length?(begins.length?' ':'')+inside.join(' '):'')+(ends.length?' '+ends[0]:'')||'1';
      pieces.push(name+'="'+escape(value)+'"');
    }
    attrs[tag]=pieces.length?' '+pieces.join(' '):'';
  }
  return {html:attrs.html,body:attrs.body,stats:{rootSelectorsInspected:inspected,rootSelectorsEmitted:usable,htmlClasses:roots.html.classes.size,bodyClasses:roots.body.classes.size,htmlAttrs:roots.html.attributes.size,bodyAttrs:roots.body.attributes.size}};
}
