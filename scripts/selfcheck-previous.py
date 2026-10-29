#!/usr/bin/env python3
"""Reuse the prior successful Selenium artifact for a fully automatic trend."""
import io
import json
import os
import pathlib
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import zipfile

class SafeArtifactRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host=(urlsplit(newurl).hostname or '').lower()
        trusted=(host=='api.github.com' or host.endswith('.githubusercontent.com') or
                 host.endswith('.github.com') or host.endswith('.blob.core.windows.net'))
        if not trusted or urlsplit(newurl).scheme!='https':
            raise urllib.error.URLError('Unexpected GitHub artifact redirect destination')
        followed=super().redirect_request(req,fp,code,msg,headers,newurl)
        # The GitHub API response redirects to a pre-signed storage URL. Never
        # forward the repository token to the storage provider.
        if host!='api.github.com':
            followed.remove_header('Authorization')
            followed.remove_header('X-github-api-version')
        return followed

_opener=urllib.request.build_opener(SafeArtifactRedirect)


def get(url, token):
    req=urllib.request.Request(url,headers={
      "Accept":"application/vnd.github+json",
      "Authorization":"Bearer "+token,
      "X-GitHub-Api-Version":"2022-11-28",
      "User-Agent":"wappalyzer-pages-selenium-selfcheck"
    })
    with _opener.open(req,timeout=30) as response:
        return response.read(15*1024*1024)

def main():
    cached=pathlib.Path('.selfcheck/cached-report.json')
    if cached.is_file():
        try:
            data=json.loads(cached.read_text(encoding='utf-8'))
            if data.get('technologies') and data.get('engine'):
                pathlib.Path('.selfcheck/previous-report.json').write_text(
                    json.dumps(data,ensure_ascii=False,separators=(',',':')),encoding='utf-8')
                print('Restored prior Selenium run from GitHub Actions cache ('+
                      str(len(data['technologies']))+' technologies).')
                return
        except (ValueError,OSError,KeyError) as exc:
            print('Could not read the previous Actions cache:',type(exc).__name__)
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
                print('Skipped previous artifact',a.get('id'),':',type(exc).__name__,str(exc)[:160])
        print('No earlier compatible Selenium artifact; this run establishes the baseline.')
    except (ValueError,urllib.error.URLError,TimeoutError) as exc:
        print('Previous Selenium artifact lookup unavailable:',type(exc).__name__,str(exc)[:160])

if __name__=='__main__':
    main()
