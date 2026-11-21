import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request
import zipfile
import shutil

RUNTIMES={
 'xray-linux':('XTLS/Xray-core','v26.7.28','Xray-linux-64.zip','xray'),
 'xray-windows':('XTLS/Xray-core','v26.7.28','Xray-windows-64.zip','xray.exe'),
 'mtg-linux':('9seconds/mtg','v2.3.0','mtg-2.3.0-linux-amd64.tar.gz','mtg'),
}

def download(url,limit=100*1024*1024):
    request=urllib.request.Request(url,headers={'User-Agent':'RelayDock/2.0','Accept':'application/vnd.github+json' if 'api.github.com' in url else '*/*'})
    with urllib.request.urlopen(request,timeout=45) as response:
        value=response.read(limit+1)
    if len(value)>limit:raise ValueError('Загрузка превысила допустимый размер')
    return value

def fetch(name,directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    repo,tag,asset,binary=RUNTIMES[name]
    target=directory/(name+('.exe' if name.endswith('windows') else ''))
    receipt=directory/(name+'.json')
    bundled=Path(__file__).parent/'bundled_runtime'
    if not target.exists() and (bundled/target.name).is_file() and (bundled/receipt.name).is_file():
        record=json.loads((bundled/receipt.name).read_text())
        data=(bundled/target.name).read_bytes()
        if record.get('tag')==tag and hashlib.sha256(data).hexdigest()==record.get('binary_sha256'):
            target.write_bytes(data);target.chmod(0o755);shutil.copyfile(bundled/receipt.name,receipt)
    if target.is_file() and receipt.is_file():
        value=json.loads(receipt.read_text())
        if value.get('tag')==tag and value.get('binary_sha256')==hashlib.sha256(target.read_bytes()).hexdigest():return target
    release=json.loads(download(f'https://api.github.com/repos/{repo}/releases/tags/{tag}',4*1024*1024))
    item=next(item for item in release['assets'] if item['name']==asset)
    digest=item.get('digest','')
    if not digest.startswith('sha256:') or len(digest)!=71:raise RuntimeError('Релиз не содержит проверяемую SHA-256. Установка остановлена.')
    data=download(item['browser_download_url'])
    if hashlib.sha256(data).hexdigest()!=digest[7:]:raise RuntimeError('Контрольная сумма загрузки не совпала.')
    if asset.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            matches=[x for x in archive.namelist() if Path(x).name==binary]
            if len(matches)!=1:raise RuntimeError('Неожиданное содержимое релиза')
            content=archive.read(matches[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
            matches=[x for x in archive if x.isfile() and Path(x.name).name==binary]
            if len(matches)!=1:raise RuntimeError('Неожиданное содержимое релиза')
            content=archive.extractfile(matches[0]).read()
    temporary=target.with_suffix('.download')
    temporary.write_bytes(content);temporary.replace(target)
    target.chmod(0o755)
    receipt.write_text(json.dumps({'tag':tag,'archive_sha256':digest[7:],'binary_sha256':hashlib.sha256(content).hexdigest()}))
    return target
