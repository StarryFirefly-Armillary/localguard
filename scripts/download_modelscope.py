from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request

ROOT = Path(os.environ.get('LOCALGUARD_TRAIN_ROOT', 'C:/LocalGuard/training'))
DESTINATION = ROOT/'base-model'
BASE = 'https://modelscope.cn/api/v1/models/Qwen/Qwen3.5-4B'
REVISION = 'f09dfc75214c5f2f4940ae6a26c126ce93828a9b'
ALLOWED = {'.json','.safetensors','.jinja','.txt','.model','.tiktoken'}


def verify(path, metadata):
    if path.stat().st_size != metadata['Size']:
        raise ValueError('Download size mismatch: '+metadata['Path'])
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream,'sha256').hexdigest()
    if digest != metadata['Sha256']:
        raise ValueError('Download SHA-256 mismatch: '+metadata['Path'])
    return {'name':metadata['Path'],'bytes':metadata['Size'],'sha256':digest}


def download(metadata):
    name = metadata['Path']
    if Path(name).name != name or any(char in name for char in ('/','\\',':')):
        raise ValueError('Unexpected upstream file path')
    target = DESTINATION/name
    partial = DESTINATION/(name+'.partial')
    if target.exists():
        return verify(target,metadata)
    url = BASE+'/repo?'+urllib.parse.urlencode({'Revision':REVISION,'FilePath':name})
    print('Downloading '+name,flush=True)
    subprocess.run(['curl','-q','--noproxy','*','--fail','--location','--silent','--show-error',
                    '--connect-timeout','30','--max-time','1200','--speed-time','90','--speed-limit','1024',
                    '--retry','3','--continue-at','-',
                    '--output',str(partial),url],check=True)
    result = verify(partial,metadata)
    partial.rename(target)
    print('Verified '+name,flush=True)
    return result


def main():
    if not ROOT.is_dir() or not DESTINATION.is_dir():
        raise RuntimeError('Create the approved LocalGuard training directories first')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    manifest_url = BASE+'/repo/files?'+urllib.parse.urlencode({'Revision':REVISION,'Recursive':'true'})
    with opener.open(manifest_url,timeout=45) as response:
        manifest = json.load(response)
    if manifest.get('Code') != 200 or not manifest.get('Success'):
        raise RuntimeError('Official ModelScope manifest is unavailable')
    files = [item for item in manifest['Data']['Files'] if item['Type']=='blob' and
             (Path(item['Path']).suffix in ALLOWED or item['Path']=='LICENSE')]
    if not any(item['Path']=='config.json' for item in files) or not any(item['Path'].endswith('.safetensors') for item in files):
        raise RuntimeError('Manifest lacks native model configuration or weights')
    pin = {'source':'Qwen official ModelScope distribution','repo':'Qwen/Qwen3.5-4B',
           'revision':REVISION,'revision_namespace':'modelscope','manifest_url':manifest_url,
           'files':files,'note':'This revision is not asserted to be a Hugging Face commit.'}
    (ROOT/'artifacts'/'modelscope-revision.json').write_text(json.dumps(pin,indent=2),encoding='utf-8')
    files.sort(key=lambda item: (item['Path'].endswith('.safetensors'), item['Path']))
    with ThreadPoolExecutor(max_workers=2) as pool:
        verified = list(pool.map(download,files))
    config = json.loads((DESTINATION/'config.json').read_text('utf-8'))
    if config.get('architectures') != ['Qwen3_5ForConditionalGeneration'] or config.get('quantization_config'):
        raise RuntimeError('Unexpected model architecture or quantized checkpoint')
    result = {'complete':True,'source':'modelscope','revision':REVISION,'verified_at':datetime.now(timezone.utc).isoformat(),
              'destination':str(DESTINATION),'bytes':sum(item['bytes'] for item in verified),'files':verified}
    (ROOT/'artifacts'/'model-download.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'complete':True,'files':len(verified),'bytes':result['bytes'],'revision':REVISION},indent=2))


if __name__=='__main__':
    main()
