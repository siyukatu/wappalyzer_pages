#!/usr/bin/env python3
"""Inspect the actual Wappalyzer CRX installed in a throwaway Selenium Chrome profile."""
import json,os,pathlib,re,shutil,time,subprocess,unicodedata
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait

PATH=str(pathlib.Path('.selfcheck/extension').resolve())
URL='https://wappalyzer-technologies.pages.dev/'
opts=Options()
opts.set_capability('goog:loggingPrefs',{'browser':'ALL'})
for arg in ['--headless=new','--no-sandbox','--disable-dev-shm-usage','--disable-gpu','--no-first-run',
            '--disable-background-networking','--disable-default-apps','--window-size=1200,800',
            '--disable-extensions-except='+PATH,'--load-extension='+PATH]:
    opts.add_argument(arg)
cft=pathlib.Path('.selfcheck/cft')
cfbrowser=cft/'chrome-linux64/chrome'
cfdriver=cft/'chromedriver-linux64/chromedriver'
if cfbrowser.is_file() and cfdriver.is_file():
    opts.binary_location=str(cfbrowser.resolve())
    check=subprocess.run([str(cfbrowser.resolve()),'--version'],capture_output=True,text=True,timeout=15)
    print('CHROME_FOR_TESTING_CHECK',repr((check.returncode,check.stdout.strip(),check.stderr.strip()[:300])),flush=True)
    logpath=pathlib.Path('.selfcheck/cft-chromedriver.log')
    try:
        driver=webdriver.Chrome(service=Service(executable_path=str(cfdriver.resolve()),log_output=str(logpath),service_args=['--verbose']),options=opts)
    except Exception:
        if logpath.is_file():print('CHROMEDRIVER_ERROR_LOG',logpath.read_text(errors='replace')[-4500:],flush=True)
        raise
else:
    binary=shutil.which('google-chrome') or shutil.which('chromium')
    if binary:opts.binary_location=binary
    driver=webdriver.Chrome(options=opts)
driver.set_script_timeout(70)
try:
    driver.set_page_load_timeout(120)
    driver.get(URL)
    WebDriverWait(driver,30).until(lambda d:d.execute_script('return document.readyState')=='complete')
    page_loaded_at=time.monotonic()
    page_window=driver.current_window_handle
    expected=os.getenv('EXPECTED_COMMIT')
    head_commit=driver.execute_script(
        'return document.querySelector(\'meta[name="wappalyzer-pages-commit"]\')?.content||null')
    if expected and head_commit!=expected:
        raise RuntimeError('Native CRX scan reached stale Pages commit '+str(head_commit)+
                           ', expected '+expected)
    print('NATIVE_PAGE_COMMIT',head_commit,flush=True)
    time.sleep(5)
    targets=driver.execute_cdp_cmd('Target.getTargets',{}).get('targetInfos',[])
    extTargets=[{'type':x.get('type'),'url':x.get('url','')[:350]} for x in targets if x.get('url','').startswith('chrome-extension://')]
    ids=sorted(set(re.findall(r'chrome-extension://([a-p]{32})/',json.dumps(extTargets))))
    print('EXTENSION_TARGETS',json.dumps(extTargets[:20],ensure_ascii=False))
    print('EXTENSION_IDS',json.dumps(ids))
    output={'extensions':ids,'targets':extTargets,'browser':driver.capabilities.get('browserVersion')}
    if not ids:raise RuntimeError('CRX extension was not actually loaded by Selenium Chrome')
    extid=ids[0]
    # Activate the real extension's own UI; never evaluate or emulate its matching engine.
    driver.switch_to.new_window('tab')
    driver.get('chrome-extension://'+extid+'/html/popup.html')
    time.sleep(3)
    print('POPUP_URL',driver.current_url)
    print('POPUP_BODY',repr(driver.execute_script('return document.body?.innerText||""')[:2400]))
    print('POPUP_HTML',repr(driver.page_source[:1400]))
    try:
        data=driver.execute_async_script("""
const done=arguments[arguments.length-1];
try {chrome.storage.local.get(null,result=>done({data:result,error:chrome.runtime.lastError?.message}))}
catch(e){done({error:String(e)})}
""")
        output['storageKeys']=list((data.get('data') or {}).keys())
        output['storageTypes']={k:str(type(v).__name__) for k,v in (data.get('data') or {}).items()}
        output['storageData']=data.get('data')
        output['storageError']=data.get('error')
        print('STORAGE_KEYS',output['storageKeys'][:70])
        print('STORAGE_TYPES',output['storageTypes'])
        print('STORAGE_EXAMPLE',json.dumps({k:v for k,v in list((data.get('data') or {}).items())[:3]},ensure_ascii=False)[:3300])
    except Exception as exc:
        print('STORAGE_ERROR',repr(exc)[:400])
    try:
        tabs=driver.execute_async_script("""
const done=arguments[arguments.length-1];
chrome.tabs.query({}, tabs=>done(tabs.map(x=>({id:x.id,url:x.url,active:x.active}))));
""")
        print('TABS',json.dumps(tabs)[:1300])
    except Exception as exc:print('TABS_ERROR',str(exc)[:250])
    # The real content.js runs an initial JS/DOM scan and then a delayed JS
    # rescan (five seconds after its initial pipeline). Requirements can trigger
    # additional DOM scans. A single read is therefore too early.
    #
    # Poll the extension's *own* background API for up to ~105 s, and require
    # at least 60 s and 20 s without new names before considering it stable.
    # Keep the largest observed result as a safeguard against transient empty
    # replies, and record all snapshots for reproducible diagnostics.
    native_js = """
const done=arguments[arguments.length-1];
chrome.tabs.query({},tabs=>{
  const page=tabs.find(t=>(t.url||'').startsWith('https://wappalyzer-technologies.pages.dev/'));
  if(!page){done({results:[],error:'No target Pages tab'});return}
  chrome.runtime.sendMessage(
    {source:'selenium-native-extension',func:'getDetectionsForTab',
     args:[{id:page.id,url:page.url}]},
    result=>done({tabId:page.id,url:page.url,results:Array.isArray(result)?result:[],
      error:chrome.runtime.lastError?.message||null})
  );
});
"""
    timeline=[]
    seen=set()
    previous=set()
    best=[]
    best_count=0
    stable_at=None
    last_change=time.monotonic()
    native_error=None
    checkpoints=[0,5,10,15,22,30,40,50,60,75,90,105]
    for scheduled_second in checkpoints:
        delay=scheduled_second-(time.monotonic()-page_loaded_at)
        if delay>0:
            time.sleep(delay)
        elapsed=round(time.monotonic()-page_loaded_at,2)
        try:
            response=driver.execute_async_script(native_js)
            detections=response.get('results') or []
            native_error=response.get('error')
        except Exception as exc:
            detections=[]
            native_error=str(exc)[:250]
        distinct={}
        for item in detections:
            if not isinstance(item,dict) or not item.get('name'):
                continue
            key=unicodedata.normalize('NFKC',str(item['name'])).casefold()
            distinct[key]=item
        current=set(distinct)
        additions=current-previous
        removals=previous-current
        seen.update(current)
        if len(current)>=best_count and not native_error:
            best=list(distinct.values())
            best_count=len(current)
        if previous!=current:
            last_change=time.monotonic()
        previous=current
        quiet=round(time.monotonic()-last_change,2)
        point={
            'secondsAfterPageLoad':elapsed,
            'detected':len(current),
            'newNames':len(additions),
            'lostNames':len(removals),
            'cumulativeDistinct':len(seen),
            'quietSeconds':quiet,
            'error':native_error,
            'addedExamples':[distinct[k]['name'] for k in sorted(additions)[:15]]
        }
        timeline.append(point)
        print('NATIVE_DETECTION_TIMELINE',json.dumps(point,ensure_ascii=False),flush=True)
        # Never stop in the first seconds of a page visit: Wappalyzer's delayed
        # js.js pass and repeated dom.js analyses must have time to complete.
        if elapsed>=60 and quiet>=20 and len(timeline)>=4 and not native_error:
            stable_at=elapsed
            break
    output['nativeTimeline']=timeline
    output['nativeDetections']=best
    output['nativeError']=None if best_count>=1000 else native_error
    output['nativeSampling']={
        'firstCount':timeline[0]['detected'] if timeline else 0,
        'lastCount':timeline[-1]['detected'] if timeline else 0,
        'peakCount':best_count,
        'cumulativeDistinct':len(seen),
        'durationSeconds':timeline[-1]['secondsAfterPageLoad'] if timeline else 0,
        'stableAtSeconds':stable_at,
        'stabilized':stable_at is not None,
        'checkpoints':len(timeline)
    }
    print('NATIVE_EXTENSION_RESULT',json.dumps({
        'count':best_count,'first':output['nativeSampling']['firstCount'],
        'last':output['nativeSampling']['lastCount'],
        'peak':best_count,'stabilized':stable_at is not None,
        'durationSeconds':output['nativeSampling']['durationSeconds'],
        'sample':[d['name'] for d in best[:20]],
        'error':output['nativeError']
    },ensure_ascii=False),flush=True)

    # The DevTools console can log dom.js twice because dependent technologies
    # trigger additional passes. Record logs, but do not interpret them as two
    # detections: the resolved technology names are deduplicated above.
    console_signals=[]
    resource_signals=[]
    try:
        driver.switch_to.window(page_window)
        for entry in driver.get_log('browser'):
            msg=entry.get('message','')
            if re.search(r'(?:dom|js)\.js|wappalyzer',msg,re.I):
                console_signals.append({
                    'level':entry.get('level'),
                    'timestamp':entry.get('timestamp'),
                    'message':msg[:450]
                })
        resource_signals=driver.execute_script("""
return performance.getEntriesByType('resource')
  .filter(r=>/chrome-extension:|\/(?:dom|js)\.js(?:\?|$)/i.test(r.name))
  .map(r=>({url:r.name.slice(0,350),startTime:r.startTime,duration:r.duration}))
  .slice(-60)
""")
    except Exception as exc:
        print('EXTENSION_INJECTION_DIAGNOSTIC_ERROR',str(exc)[:250])
    finally:
        driver.switch_to.window(driver.window_handles[-1])
    output['injectionDiagnostics']={
        'consoleSignals':console_signals[-50:],
        'resourceSignals':resource_signals,
        'domJsConsoleMentions':sum('dom.js' in x['message'].lower() for x in console_signals),
        'jsJsConsoleMentions':sum('js.js' in x['message'].lower() for x in console_signals)
    }
    print('NATIVE_INJECTION_DIAGNOSTICS',json.dumps({
        'domJsConsoleMentions':output['injectionDiagnostics']['domJsConsoleMentions'],
        'jsJsConsoleMentions':output['injectionDiagnostics']['jsJsConsoleMentions'],
        'scriptResourceSignals':len(resource_signals)
    }),flush=True)
    output['popupText']=driver.execute_script('return document.body?.innerText||""')
    output['popupHtml']=driver.page_source[:30000]
    pathlib.Path('.selfcheck/extension-probe.json').write_text(json.dumps(output,ensure_ascii=False),encoding='utf-8')
finally:
    driver.quit()
