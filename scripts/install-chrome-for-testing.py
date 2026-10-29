#!/usr/bin/env python3
"""Install official Chrome for Testing (which supports unpacked extensions)."""
import io,json,os,pathlib,stat,urllib.request,zipfile
API='https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json'
DEST=pathlib.Path('.selfcheck/cft')
def fetch(url,limit):
    req=urllib.request.Request(url,headers={'User-Agent':'wappalyzer-selenium-selfcheck'})
    with urllib.request.urlopen(req,timeout=90) as response:
        data=response.read(limit+1)
    if len(data)>limit:raise ValueError('Chrome for Testing package is unexpectedly large')
    return data
def main():
    meta=json.loads(fetch(API,2*1024*1024))
    stable=meta['channels']['Stable']
    for name in ('chrome','chromedriver'):
        url=next(v['url'] for v in stable['downloads'][name] if v['platform']=='linux64')
        archive=zipfile.ZipFile(io.BytesIO(fetch(url,220*1024*1024)))
        for entry in archive.infolist():
            if entry.is_dir():continue
            parts=pathlib.PurePosixPath(entry.filename).parts
            if not parts or '..' in parts or entry.filename.startswith('/'):raise ValueError('Invalid Chrome for Testing ZIP')
            path=DEST.joinpath(*parts)
            path.parent.mkdir(parents=True,exist_ok=True)
            with archive.open(entry) as src,open(path,'wb') as dest:
                while chunk:=src.read(65536):dest.write(chunk)
            if (entry.external_attr >> 16) & 0o111:
                path.chmod(path.stat().st_mode|stat.S_IXUSR|stat.S_IXGRP|stat.S_IXOTH)
        filename=DEST/('chrome-linux64/chrome' if name=='chrome' else 'chromedriver-linux64/chromedriver')
        filename.chmod(filename.stat().st_mode|stat.S_IXUSR|stat.S_IXGRP|stat.S_IXOTH)
    print(json.dumps({'chromeForTesting':stable['version'],'binary':str(DEST/'chrome-linux64/chrome'),'chromedriver':str(DEST/'chromedriver-linux64/chromedriver')}))
if __name__=='__main__':main()
