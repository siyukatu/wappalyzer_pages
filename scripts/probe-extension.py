#!/usr/bin/env python3
"""Inspect the actual Wappalyzer CRX installed in a throwaway Selenium Chrome profile."""
import json,os,pathlib,re,shutil,time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait

PATH=str(pathlib.Path('.selfcheck/extension').resolve())
URL='https://wappalyzer-technologies.pages.dev/'
opts=Options()
for arg in ['--headless=new','--no-sandbox','--disable-dev-shm-usage','--disable-gpu','--no-first-run',
            '--disable-background-networking','--disable-default-apps','--window-size=1200,800',
            '--disable-extensions-except='+PATH,'--load-extension='+PATH]:
    opts.add_argument(arg)
bin=shutil.which('google-chrome') or shutil.which('chromium')
if bin:opts.binary_location=bin
driver=webdriver.Chrome(options=opts)
try:
    driver.set_page_load_timeout(120)
    driver.get(URL)
    WebDriverWait(driver,30).until(lambda d:d.execute_script('return document.readyState')=='complete')
    time.sleep(4)
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
    output['popupText']=driver.execute_script('return document.body?.innerText||""')
    output['popupHtml']=driver.page_source[:30000]
    pathlib.Path('.selfcheck/extension-probe.json').write_text(json.dumps(output,ensure_ascii=False),encoding='utf-8')
finally:
    driver.quit()
