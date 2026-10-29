#!/usr/bin/env python3
"""Inspect the actual Wappalyzer CRX installed in a throwaway Selenium Chrome profile."""
import json,os,pathlib,re,shutil,time,subprocess
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait

PATH=str(pathlib.Path('.selfcheck/extension').resolve())
URL='https://wappalyzer-technologies.pages.dev/'
opts=Options()
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
    # Ask the extension's own background driver for resolved detections. This
    # calls Driver.getDetectionsForTab, not a replica of its matching logic.
    try:
        native=driver.execute_async_script("""
const finish=arguments[arguments.length-1];
chrome.tabs.query({}, tabs=>{
  const page=tabs.find(t=>(t.url||'').startsWith('https://wappalyzer-technologies.pages.dev/'));
  if(!page)return finish({error:'Target Pages tab missing from extension tab list'});
  chrome.runtime.sendMessage(
    {source:'selenium-native-extension',func:'getDetectionsForTab',args:[{id:page.id,url:page.url}]},
    result=>finish({tabId:page.id,url:page.url,results:result,
      error:chrome.runtime.lastError?.message||null})
  );
});
""")
        output['nativeError']=native.get('error')
        output['nativeDetections']=native.get('results') or []
        print('NATIVE_EXTENSION_RESULT',json.dumps({
            'count':len(output['nativeDetections']),
            'sample':[v.get('name') for v in output['nativeDetections'][:25]],
            'error':output['nativeError'],'tabId':native.get('tabId')
        },ensure_ascii=False))
    except Exception as exc:
        output['nativeError']=str(exc)[:600]
        print('NATIVE_EXTENSION_ERROR',output['nativeError'])
    output['popupText']=driver.execute_script('return document.body?.innerText||""')
    output['popupHtml']=driver.page_source[:30000]
    pathlib.Path('.selfcheck/extension-probe.json').write_text(json.dumps(output,ensure_ascii=False),encoding='utf-8')
finally:
    driver.quit()
