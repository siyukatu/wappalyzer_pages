#!/usr/bin/env python3
"""Reuse the prior successful Selenium artifact for a fully automatic trend."""
import io
import json
import os
import pathlib
import urllib.error
import urllib.request
import zipfile

def get(url, token):
    req=urllib.request.Request(url,headers={
      "Accept":"application/vnd.github+json",
      "Authorization":"Bearer "+token,
      "X-GitHub-Api-Version":"2022-11-28",
      "User-Agent":"wappalyzer-pages-selenium-selfcheck"
    })
    with urllib.request.urlopen(req,timeout=30) as response:
        return response.read(15*1024*1024)

def main():
    token=os.getenv('GITHUB_TOKEN','')
    repo=os.getenv('GITHUB_REPOSITORY','')
    if not token or '/' not in repo:
        print('Previous Selenium comparison unavailable (no GitHub Actions token).')
        return
    try:
        listing=json.loads(get(
          'https://api.github.com/repos/'+repo+'/actions/artifacts?name=selenium-selfcheck&per_page=20',token))
        items=[a for a in listing.get('artifacts',[]) if not a.get('expired') and
          a.get('name')=='selenium-selfcheck' and a.get('size_in_bytes',0)<10*1024*1024]
        items.sort(key=lambda x:x.get('created_at',''),reverse=True)
        for a in items:
            try:
                payload=get(a['archive_download_url'],token)
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    members=[f for f in archive.namelist() if f.endswith('report.json')]
                    if not members:continue
                    data=json.loads(archive.read(members[0]))
                if data.get('technologies') and data.get('engine'):
                    pathlib.Path('.selfcheck').mkdir(exist_ok=True)
                    pathlib.Path('.selfcheck/previous-report.json').write_text(
                        json.dumps(data,ensure_ascii=False,separators=(',',':')),encoding='utf-8')
                    print('Loaded previous Selenium diagnosis from artifact '+str(a['id'])+
                          ' ('+str(len(data['technologies']))+' technologies).')
                    return
            except (ValueError,KeyError,urllib.error.URLError,zipfile.BadZipFile) as exc:
                print('Skipped invalid previous diagnostic artifact:',type(exc).__name__)
        print('No earlier compatible Selenium artifact; this run establishes the baseline.')
    except (ValueError,urllib.error.URLError,TimeoutError) as exc:
        print('Previous Selenium artifact lookup unavailable:',type(exc).__name__)

if __name__=='__main__':
    main()
