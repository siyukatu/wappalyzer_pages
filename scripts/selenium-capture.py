#!/usr/bin/env python3
"""Capture the real, deployed Cloudflare Pages response with Selenium/Chromium.

No third-party requests are deliberately made. CSP enforcement is left enabled.
The raw network HTML, response headers, cookies, visible text, meta, DOM and
JavaScript signals are handed to the original open-source Wappalyzer analyzer.
"""
import argparse
import os
import re
import http.client
import base64
import json
import pathlib
import shutil
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait

CAPTURE_JS = r"""
const paths=arguments[0], domSpecs=arguments[1];
const js={};
const toScalar=v=>typeof v==="string"||typeof v==="number"?v:!!v;
for(const chain of paths){
  try {
    const parts=chain.replace(/\[([^\]]+)\]/g,'.$1').replace(/^(window|globalThis)\./,'').replace(/^\./,'').split('.');
    let current=window;
    for(const part of parts){
      if(!part){continue}
      if(current==null||!(typeof current==='object'||typeof current==='function')||!Object.prototype.hasOwnProperty.call(current,part)){
        current=undefined;break;
      }
      current=current[part];
    }
    if(current!==undefined){js[chain]=[toScalar(current)]}
  }catch(e){}
}
const dom=[];
for(const rule of domSpecs){
  let nodes;
  try{nodes=document.querySelectorAll(rule.selector)}catch(e){continue}
  if(!nodes.length)continue;
  dom.push({name:rule.name,selector:rule.selector,exists:""});
  for(const node of [...nodes].slice(0,4)){
    if(rule.text){
      const txt=(node.textContent||'').trim().slice(0,20000);
      if(txt)dom.push({name:rule.name,selector:rule.selector,text:txt});
    }
    for(const attribute of rule.attributes){
      if(!node.hasAttribute(attribute))continue;
      dom.push({name:rule.name,selector:rule.selector,attribute,value:node.getAttribute(attribute)||''});
    }
    for(const property of rule.properties){
      if(!Object.prototype.hasOwnProperty.call(node,property))continue;
      try {dom.push({name:rule.name,selector:rule.selector,property,value:toScalar(node[property])})}catch(e){}
    }
  }
}
const meta={};
for(const el of document.querySelectorAll('meta')){
  const name=el.getAttribute('name')||el.getAttribute('property')||el.getAttribute('itemprop');
  const content=el.getAttribute('content');
  if(name&&content){(meta[name.toLowerCase()]??=[]).push(content.slice(0,20000))}
}
const scriptSrc=[];
for(const el of document.querySelectorAll('script[src]')){
  const attr=el.getAttribute('src');if(attr)scriptSrc.push(attr);
  const absolute=el.src;if(absolute)scriptSrc.push(absolute);
}
const css=Array.from(document.querySelectorAll('style')).map(e=>e.textContent||'').join('\n');
const scripts=Array.from(document.querySelectorAll('script:not([src])')).map(e=>e.textContent||'').join('\n');
return {
  url:location.href,
  htmlFallback:document.documentElement.outerHTML,
  text:(document.body?.innerText||'').slice(0,1500000),
  meta,scriptSrc:[...new Set(scriptSrc)],
  css:css.slice(0,1000000),
  scripts:scripts.slice(0,1000000),
  js,dom,
  diagnostics:{
    readyState:document.readyState,
    bodyInnerTextLength:(document.body?.innerText||'').length,
    pageSourceLength:document.documentElement.outerHTML.length,
    scripts:document.querySelectorAll('script[src]').length,
    inlineScripts:document.querySelectorAll('script:not([src])').length,
    elements:document.getElementsByTagName('*').length,
    globalPaths:Object.keys(js).length,
    matchedDomObservations:dom.length,
    cookieLength:document.cookie.length,
    inlineStyleSheets:document.querySelectorAll('style').length,
    cspStyleApplied:!!document.getElementById('wappalyzer-conceal') &&
       getComputedStyle(document.body).position==='fixed'
  }
};
"""

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--url',default='https://wappalyzer-technologies.pages.dev/')
    parser.add_argument('--specs',default='.selfcheck/specs.json')
    parser.add_argument('--output',default='.selfcheck/capture.json')
    args=parser.parse_args()
    parsed=urlparse(args.url)
    if parsed.scheme!='https' or parsed.hostname!='wappalyzer-technologies.pages.dev':
        parser.error('Self-diagnosis must target the designated Pages HTTPS hostname')
    specs=json.loads(pathlib.Path(args.specs).read_text(encoding='utf-8'))
    opts=Options()
    opts.add_argument('--headless=new')
    opts.add_argument('--no-sandbox')
    opts.add_argument('--disable-dev-shm-usage')
    opts.add_argument('--disable-gpu')
    opts.add_argument('--window-size=1440,900')
    opts.add_argument('--disable-background-networking')
    opts.add_argument('--no-first-run')
    opts.add_argument('--no-default-browser-check')
    opts.set_capability('goog:loggingPrefs',{'performance':'ALL'})
    binary=shutil.which('google-chrome') or shutil.which('chromium') or shutil.which('chromium-browser')
    if binary:
        opts.binary_location=binary
    driver=webdriver.Chrome(options=opts)
    try:
        driver.set_page_load_timeout(120)
        driver.set_script_timeout(120)
        driver.execute_cdp_cmd('Network.enable',{})
        expected=os.environ.get('EXPECTED_COMMIT','')
        if expected and not re.fullmatch('[a-f0-9]{40}',expected):
            raise RuntimeError('EXPECTED_COMMIT must be a full Git SHA')
        actual=None
        for attempt in range(25):
            driver.get(args.url)
            WebDriverWait(driver,60).until(lambda d:d.execute_script('return document.readyState') in ('interactive','complete'))
            actual=driver.execute_script(
                'return document.querySelector(\'meta[name="wappalyzer-pages-commit"]\')?.content||null')
            if not expected or actual==expected:
                print('DEPLOYMENT_MATCH',json.dumps({'expected':expected,'found':actual,'attempt':attempt+1}),flush=True)
                break
            print('WAITING_FOR_PAGES',json.dumps({'expected':expected[:12],'found':(actual or '')[:12],'attempt':attempt+1}),flush=True)
            time.sleep(10)
        else:
            raise RuntimeError('Cloudflare Pages is still not at target commit '+expected+'; found '+str(actual))
        time.sleep(2)
        page=driver.execute_script(CAPTURE_JS,specs['js'],specs['dom'])
        events=[]
        for log in driver.get_log('performance'):
            try:
                msg=json.loads(log['message'])['message']
                events.append(msg)
            except (KeyError,ValueError,TypeError):
                continue
        responses=[e for e in events if e.get('method')=='Network.responseReceived']
        documents=[e for e in responses if e['params'].get('type')=='Document' and
                   urlparse(e['params']['response'].get('url','')).hostname==parsed.hostname]
        if not documents:
            raise RuntimeError('Selenium/CDP did not observe the live document response')
        # iframe Document responses are also present. Never mistake the last
        # loaded child frame for the top-level document and its CSP/headers.
        root_docs=[e for e in documents if urlparse(e['params']['response'].get('url','')).path==parsed.path]
        if not root_docs:
            raise RuntimeError('Selenium/CDP did not observe the top-level Pages response')
        main_doc=root_docs[-1]
        shard_paths=driver.execute_script("return Array.from(document.querySelectorAll('iframe[data-wappalyzer-header-shard]'), f => new URL(f.src).pathname)")
        shard_loaded=driver.execute_script("return Array.from(document.querySelectorAll('iframe[data-wappalyzer-header-shard]')).filter(f => f.contentDocument && f.contentDocument.readyState === 'complete').length")
        shard_responses=[]
        for event in documents:
            resp=event['params']['response']
            path=urlparse(resp.get('url','')).path
            if path in shard_paths:
                shard_responses.append({'path':path,'status':int(resp.get('status',0)),
                    'headerFields':len(resp.get('headers',{}))})
        if len(shard_paths)!=len(set(shard_paths)) or shard_loaded!=len(shard_paths):
            raise RuntimeError('Not all same-origin header shard iframes loaded')
        if any(not any(x['path']==path and x['status']==200 for x in shard_responses) for path in shard_paths):
            raise RuntimeError('Selenium/CDP did not observe all static header shard HTTP 200 responses')
        response=main_doc['params']['response']
        code=int(response.get('status',0))
        if code !=200:
            raise RuntimeError(f'Live Pages returned HTTP {code}, expected 200')
        header_map={k.lower():[str(v)] for k,v in response.get('headers',{}).items()}
        for ev in events:
            if ev.get('method')=='Network.responseReceivedExtraInfo' and ev.get('params',{}).get('requestId')==main_doc['params'].get('requestId'):
                for k,v in ev['params'].get('headers',{}).items():
                    header_map[k.lower()]=[str(v)]
        html=page.pop('htmlFallback')
        cdp_raw=False
        try:
            body=driver.execute_cdp_cmd('Network.getResponseBody',{'requestId':main_doc['params']['requestId']})
            html=base64.b64decode(body['body']).decode('utf-8','replace') if body.get('base64Encoded') else body['body']
            cdp_raw=True
        except Exception as exc:
            page['diagnostics']['htmlFallbackReason']=str(exc)[:200]
        page['html']=html
        page['headers']=header_map
        cookies={}
        for cookie in driver.get_cookies():
            cookies.setdefault(cookie['name'],[]).append(cookie.get('value',''))
        page['cookies']=cookies
        # The test site intentionally emits >100 synthetic HTTP headers;
        # Python's default HTTP parser limit otherwise rejects build-info.json.
        http.client._MAXHEADERS=1000
        # Separate first-party metadata request: this is not a third-party probe.
        # It identifies stale Cloudflare Pages deployments during push-triggered checks.
        deployment={}
        try:
            url=parsed.scheme+'://'+parsed.hostname+'/build-info.json'
            request=Request(url,headers={'User-Agent':'wappalyzer-pages-selenium-diagnostics'})
            with urlopen(request,timeout=15) as reply:
                if reply.status==200:
                    raw=reply.read(300000)
                    info=json.loads(raw)
                    source=info.get('ruleSource') or {}
                    deployment={
                        'sourceCommit':info.get('sourceCommit'),
                        'generatedAt':info.get('generatedAt'),
                        'technologies':info.get('technologies'),
                        'ruleSource':source.get('type'),
                        'crxVersion':source.get('version'),
                        'crxSha256':source.get('sha256')
                    }
        except (OSError,ValueError,KeyError) as exc:
            deployment={'error':str(exc)[:160]}
        expected=os.environ.get('GITHUB_SHA')
        deployment['expectedCommit']=expected
        deployment['isLatestCommit']=bool(expected and deployment.get('sourceCommit')==expected)
        page['deployment']=deployment
        csp=' '.join(header_map.get('content-security-policy',[]))
        page['diagnostics'].update({
            'httpStatus':code,
            'responseHeaders':len(header_map),
            'headerShardFrames':len(shard_paths),
            'headerShardFramesLoaded':shard_loaded,
            'headerShardResponses':shard_responses,
            'cookieCount':len(cookies),
            'rawHtmlCapturedByCDP':cdp_raw,
            'htmlLength':len(html),
            'cspPresent':bool(csp),
            'cspBlocksExternal':'default-src \'none\'' in csp and 'connect-src \'none\'' in csp,
            'thirdPartyResponses':sorted({e['params']['response']['url'] for e in responses if
              urlparse(e['params']['response'].get('url','')).hostname not in (None,parsed.hostname)})[:20],
            'cspBlockedRequests':sum(e.get('params',{}).get('blockedReason')=='csp' for e in events if e.get('method')=='Network.loadingFailed'),
        })
        out=pathlib.Path(args.output)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(page,ensure_ascii=False,separators=(',',':')),encoding='utf-8')
        print(json.dumps({'browser':driver.capabilities.get('browserVersion'),
            'url':page['url'],**page['diagnostics']},ensure_ascii=False))
        if not csp:
            raise RuntimeError('Live deployment did not expose any CSP header')
        if not page['diagnostics']['cspStyleApplied']:
            raise RuntimeError('Concealment CSS was not applied in the deployed browser page')
    finally:
        driver.quit()

if __name__=='__main__':
    main()
