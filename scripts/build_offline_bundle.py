from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def package_versions(python):
    command = [str(python), '-c', "import importlib.metadata as m,json; print(json.dumps({d.metadata['Name']:d.version for d in m.distributions() if d.metadata['Name'].lower() not in ('localguard-audit','pip')}))"]
    return json.loads(subprocess.check_output(command, text=True, encoding='utf-8'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT/'dist'/'offline')
    parser.add_argument('--no-download', action='store_true')
    args = parser.parse_args()
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    environments = {'app': ROOT/'.localguard/app-env/Scripts/python.exe', 'scanners': ROOT/'.localguard/scanner-env/Scripts/python.exe'}
    for name, python in environments.items():
        versions = package_versions(python)
        lock = destination/(name+'.lock.txt')
        lock.write_text(''.join(f'{package}=={version}\n' for package, version in sorted(versions.items())), encoding='utf-8')
        wheelhouse = destination/('wheels-'+name)
        wheelhouse.mkdir(exist_ok=True)
        if not args.no_download:
            subprocess.run([str(python), '-m', 'pip', 'download', '--index-url', 'https://pypi.org/simple', '--only-binary=:all:',
                            '--no-deps', '--dest', str(wheelhouse), '--requirement', str(lock)], check=True)
    wheel = ROOT/'dist'/'localguard_audit-0.1.0-py3-none-any.whl'
    if not wheel.is_file():
        raise RuntimeError('Build the application wheel before preparing the offline bundle')
    shutil.copy2(wheel, destination/wheel.name)
    shutil.copytree(ROOT/'.localguard/bin', destination/'bin', dirs_exist_ok=True)
    shutil.copytree(ROOT/'.localguard/grype-db', destination/'grype-db', dirs_exist_ok=True)
    shutil.copy2(ROOT/'scripts/install_offline.py', destination/'install_offline.py')
    files = []
    for file in sorted(destination.rglob('*')):
        if not file.is_file() or file.name == 'bundle-manifest.json':
            continue
        with file.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        files.append({'path':file.relative_to(destination).as_posix(), 'bytes':file.stat().st_size, 'sha256':digest})
    manifest = {'built_at':datetime.now(timezone.utc).isoformat(), 'platform':'Windows x64', 'python':'3.13',
                'package':'localguard-audit==0.1.0', 'files':files,
                'external_model':{'required_for':'8gb local LLM and vision only', 'model':'Qwen3.5-4B Q4 GGUF',
                                  'included':False, 'runtime':'Compatible local llama-server', 'rules_mode_requires_model':False},
                'limitations':['Static rule coverage is limited and findings need human review.',
                               'The source snapshot and process Job do not provide OS-level filesystem/network isolation.',
                               'Training adapter and before/after improvement are separate, unverified deliverables.']}
    (destination/'bundle-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'bundle':str(destination), 'files':len(files), 'bytes':sum(file['bytes'] for file in files)}, indent=2))


if __name__ == '__main__':
    main()
