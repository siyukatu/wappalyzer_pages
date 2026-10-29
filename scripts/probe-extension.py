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
driver.set_script_timeout(18)
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
    popup_window=driver.current_window_handle
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
const reply=arguments[arguments.length-1];
let completed=false;
const done=value=>{if(!completed){completed=true;reply(value)}};
setTimeout(()=>done({results:[],error:'Native background query timed out'}),12000);
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
    # The toolbar badge is set by the extension's own setIcon() implementation
    # from the already-resolved technology list. It can be read independently
    # of its overloaded background message handler. The session cache provides
    # additional observation, not an alternative detection engine.
    badge_js = """
const reply=arguments[arguments.length-1];
let called=false;
const done=value=>{if(!called){called=true;reply(value)}};
setTimeout(()=>done({error:'Badge/session query timeout'}),4500);
chrome.tabs.query({},tabs=>{
  const page=tabs.find(t=>(t.url||'').startsWith('https://wappalyzer-technologies.pages.dev/'));
  if(!page){done({error:'Pages tab unavailable'});return}
  chrome.action.getBadgeText({tabId:page.id},badge=>{
    const badgeError=chrome.runtime.lastError?.message||null;
    try{
      chrome.storage.session.get(['hostnames','tabResults'],data=>{
        const storageError=chrome.runtime.lastError?.message||null;
        const host=data?.hostnames?.['wappalyzer-technologies.pages.dev'];
        const tab=data?.tabResults?.[page.id];
        done({badge,tabId:page.id,badgeError,storageError,
          hostnameRawMatches:Array.isArray(host?.detections)?host.detections.length:null,
          tabRawMatches:Array.isArray(tab?.detections)?tab.detections.length:null,
          hostnameCachedAt:host?.dateTime||null});
      });
    }catch(e){done({badge,tabId:page.id,badgeError,error:String(e)})}
  });
});
"""
    timeline=[]
    seen=set()
    previous=set()
    best=[]
    best_count=0
    stable_at=None
    last_change=time.monotonic()
    badge_last_change=time.monotonic()
    last_badge=None
    last_badge_count=None
    last_raw_count=None
    raw_last_change=time.monotonic()
    first_raw_count=None
    peak_raw_count=0
    last_valid_native_count=None
    first_valid_native_count=None
    last_native_attempt=-100
    last_native_error=None
    checkpoints=[0,5,10,15,22,30,40,50,60,75,90,105]
    for scheduled_second in checkpoints:
        if time.monotonic()-page_loaded_at>132:
            print('NATIVE_SCAN_DEADLINE',round(time.monotonic()-page_loaded_at,2),flush=True)
            break
        delay=scheduled_second-(time.monotonic()-page_loaded_at)
        if delay>0:time.sleep(delay)
        elapsed=round(time.monotonic()-page_loaded_at,2)
        # Frequent calls into a busy service worker can worsen the delay.
        # Back off after a native message timeout while still monitoring the
        # user-visible Wappalyzer badge through Chrome's action API.
        should_query=(last_native_error is None or
                      elapsed-last_native_attempt>=25)
        native_error=None
        successful=False
        distinct={}
        if should_query:
            last_native_attempt=elapsed
            try:
                response=driver.execute_async_script(native_js)
                detections=response.get('results') or []
                native_error=response.get('error')
                successful=not native_error
            except Exception as exc:
                detections=[]
                native_error=str(exc)[:250]
            if successful:
                for item in detections:
                    if not isinstance(item,dict) or not item.get('name'):
                        continue
                    key=unicodedata.normalize('NFKC',str(item['name'])).casefold()
                    distinct[key]=item
                last_native_error=None
            else:
                last_native_error=native_error
        current=set(distinct) if successful else previous
        additions=current-previous if successful else set()
        removals=previous-current if successful else set()
        if successful:
            seen.update(current)
            last_valid_native_count=len(current)
            if first_valid_native_count is None:
                first_valid_native_count=len(current)
            if len(current)>=best_count:
                best=list(distinct.values())
                best_count=len(current)
            if previous!=current:
                last_change=time.monotonic()
            previous=current

        badge={}
        try:
            badge=driver.execute_async_script(badge_js)
        except Exception as exc:
            badge={'error':str(exc)[:250]}
        badge_text=str(badge.get('badge') or '')
        badge_count=int(badge_text) if badge_text.isdecimal() else None
        if badge_count is not None:
            if last_badge_count!=badge_count:
                badge_last_change=time.monotonic()
            last_badge_count=badge_count
        tab_raw=badge.get('tabRawMatches')
        if isinstance(tab_raw,int):
            if first_raw_count is None:first_raw_count=tab_raw
            if last_raw_count!=tab_raw:raw_last_change=time.monotonic()
            last_raw_count=tab_raw
            peak_raw_count=max(peak_raw_count,tab_raw)
        quiet=round(time.monotonic()-last_change,2)
        badge_quiet=round(time.monotonic()-badge_last_change,2)
        raw_quiet=round(time.monotonic()-raw_last_change,2)
        point={
            'secondsAfterPageLoad':elapsed,
            'detected':last_valid_native_count,
            'nativeQueryOk':successful,
            'newNames':len(additions),
            'lostNames':len(removals),
            'cumulativeDistinct':len(seen),
            'quietSeconds':quiet,
            'badgeText':badge_text,
            'badgeCount':badge_count,
            'badgeQuietSeconds':badge_quiet,
            'rawQuietSeconds':raw_quiet,
            'hostnameRawMatches':badge.get('hostnameRawMatches'),
            'tabRawMatches':badge.get('tabRawMatches'),
            'error':native_error or badge.get('error') or badge.get('storageError'),
            'addedExamples':[distinct[k]['name'] for k in sorted(additions)[:15]]
        }
        timeline.append(point)
        print('NATIVE_DETECTION_TIMELINE',json.dumps(point,ensure_ascii=False),flush=True)
        # The last two badge observations are at least 20 seconds apart and
        # must agree; settle no sooner than a minute after page load.
        if (elapsed>=60 and badge_count is not None and
            badge_quiet>=20 and raw_quiet>=20 and len(timeline)>=4 and best_count>=1000):
            stable_at=elapsed
            break
    output['nativeTimeline']=timeline
    output['nativeDetections']=best
    output['nativeError']=None if best_count>=1000 else last_native_error
    output['nativeSampling']={
        'firstCount':first_valid_native_count,
        'lastCount':last_valid_native_count,
        'peakCount':best_count,
        'cumulativeDistinct':len(seen),
        'firstBadgeCount':next((p['badgeCount'] for p in timeline if p['badgeCount'] is not None),None),
        'lastBadgeCount':last_badge_count,
        'peakBadgeCount':max((p['badgeCount'] or 0 for p in timeline),default=0),
        'firstRawMatches':first_raw_count,
        'lastRawMatches':last_raw_count,
        'peakRawMatches':peak_raw_count,
        'durationSeconds':timeline[-1]['secondsAfterPageLoad'] if timeline else 0,
        'stableAtSeconds':stable_at,
        'stabilized':stable_at is not None,
        'checkpoints':len(timeline),
        'backgroundUnavailableAtEnd':bool(last_native_error)
    }
    print('NATIVE_EXTENSION_RESULT',json.dumps({
        'count':best_count,'first':first_valid_native_count,
        'last':last_valid_native_count,
        'peakBadge':output['nativeSampling']['peakBadgeCount'],
        'lastBadge':last_badge_count,
        'firstRaw':first_raw_count,'lastRaw':last_raw_count,'peakRaw':peak_raw_count,
        'stabilized':stable_at is not None,
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
            if re.search(r'(?:dom|js)\.js|chrome-extension:|wappalyzer:response|wappalyzer:detach',msg,re.I):
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
        driver.switch_to.window(popup_window)
    output['injectionDiagnostics']={
        'consoleSignals':console_signals[-70:],
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
