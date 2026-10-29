#!/usr/bin/env python3
"""Unpack a Web Store CRX ZIP into a dedicated temporary Selenium profile folder."""
import json
import pathlib
import sys
import zipfile
from pathlib import PurePosixPath

def main():
    source=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '.selfcheck/wappalyzer.zip')
    out=pathlib.Path(sys.argv[2] if len(sys.argv)>2 else '.selfcheck/extension')
    out.mkdir(parents=True,exist_ok=True)
    files=0
    bytes_unpacked=0
    with zipfile.ZipFile(source) as archive:
        for obj in archive.infolist():
            parts=PurePosixPath(obj.filename).parts
            if not parts or any(x in ('','..','.') for x in parts) or obj.filename.startswith('/'):
                raise ValueError('Invalid ZIP entry path')
            if obj.is_dir():continue
            if obj.file_size>20*1024*1024 or bytes_unpacked+obj.file_size>180*1024*1024:
                raise ValueError('Unpacked Chrome extension exceeds allowed size')
            target=out.joinpath(*parts)
            target.parent.mkdir(parents=True,exist_ok=True)
            with archive.open(obj,'r') as src,open(target,'wb') as dest:
                while True:
                    chunk=src.read(65536)
                    if not chunk:break
                    dest.write(chunk)
            files+=1
            bytes_unpacked+=obj.file_size
    manifest=json.loads((out/'manifest.json').read_text(encoding='utf-8'))
    meta={
      'extensionManifestVersion':manifest.get('manifest_version'),
      'version':manifest.get('version'),
      'name':manifest.get('name'),
      'background':manifest.get('background'),
      'action':manifest.get('action'),
      'permissions':manifest.get('permissions'),
      'host_permissions':manifest.get('host_permissions'),
      'content_scripts':manifest.get('content_scripts'),
      'fileCount':files,
      'unpackedBytes':bytes_unpacked,
      'topLevelFiles':sorted({p.parts[0] for p in out.iterdir()})
    }
    print(json.dumps(meta,ensure_ascii=False)[:10000])
    (out.parent/'extension-manifest-info.json').write_text(json.dumps(meta,ensure_ascii=False),encoding='utf-8')
if __name__=='__main__':
    main()
