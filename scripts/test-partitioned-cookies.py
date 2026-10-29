#!/usr/bin/env python3
"""Verify browser-visible partitioned cookies without altering deployed pages."""
import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait

opts=Options()
for flag in ('--headless=new','--no-sandbox','--disable-dev-shm-usage','--no-first-run','--disable-background-networking'):
    opts.add_argument(flag)
driver=webdriver.Chrome(options=opts)
try:
    driver.set_page_load_timeout(60)
    driver.get('https://wappalyzer-technologies.pages.dev/404.html')
    WebDriverWait(driver,30).until(lambda d:d.execute_script('return document.readyState')=='complete')
    driver.execute_cdp_cmd('Network.clearBrowserCookies',{})
    result=driver.execute_script("""
        const count=110;
        for(let i=0;i<count;i++) document.cookie='__wc_regular_'+i+'=1; Path=/; Secure; SameSite=Lax';
        for(let i=0;i<count;i++) document.cookie='__wc_partitioned_'+i+'=1; Path=/; Secure; SameSite=None; Partitioned';
        const cookies=document.cookie.split('; ').filter(Boolean);
        return {
          regular:cookies.filter(x=>x.startsWith('__wc_regular_')).length,
          partitioned:cookies.filter(x=>x.startsWith('__wc_partitioned_')).length,
          total:cookies.length, cookieEnabled:navigator.cookieEnabled,
          expectedEach:count
        };
    """)
    result['chrome']=driver.capabilities.get('browserVersion')
    print('PARTITIONED_COOKIE_CAPACITY '+json.dumps(result),flush=True)
    if result['partitioned']<100 or result['regular']<100:
        print('CHIPS coexistence NOT demonstrated; do not deploy a dual-jar patch.',flush=True)
    else:
        print('CHIPS coexistence VERIFIED; dual cookie namespace is viable.',flush=True)
finally:
    driver.quit()
