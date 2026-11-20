from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv


def verify_bundle(bundle):
    manifest = json.loads((bundle/'bundle-manifest.json').read_text('utf-8'))
    for item in manifest['files']:
        relative = Path(item['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unsafe bundle manifest path')
        file = (bundle/relative).resolve(strict=True)
        if not file.is_relative_to(bundle) or file.stat().st_size != item['bytes']:
            raise ValueError('Bundle file is missing or has the wrong size: '+item['path'])
        with file.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != item['sha256']:
            raise ValueError('Bundle checksum mismatch: '+item['path'])
    return manifest


def main():
    parser = argparse.ArgumentParser(description='Install a verified LocalGuard offline bundle into a NEW directory without network access')
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--allowed-root', type=Path, action='append', required=True)
    parser.add_argument('--model-path', type=Path)
    parser.add_argument('--model-binary', type=Path)
    parser.add_argument('--model-library-dir', type=Path, action='append', default=[])
    parser.add_argument('--mmproj-path', type=Path)
    args = parser.parse_args()
    if os.name != 'nt' or sys.version_info[:2] != (3,13):
        raise ValueError('This wheel bundle requires Windows x64 and Python 3.13')
    bundle = Path(__file__).resolve().parent
    verify_bundle(bundle)
    destination = args.destination.resolve()
    if destination.exists():
        raise ValueError('Use a new destination; existing installations are never overwritten')
    roots = [str(root.resolve(strict=True)) for root in args.allowed_root]
    if any(not Path(root).is_dir() for root in roots):
        raise ValueError('Every allowed-root must be an existing directory')
    if bool(args.model_path) != bool(args.model_binary):
        raise ValueError('Provide both model-path and model-binary for the 8gb tier')
    model = str(args.model_path.resolve(strict=True)) if args.model_path else ''
    binary = str(args.model_binary.resolve(strict=True)) if args.model_binary else ''
    libraries = [str(path.resolve(strict=True)) for path in args.model_library_dir]
    projector = str(args.mmproj_path.resolve(strict=True)) if args.mmproj_path else ''
    destination.mkdir(parents=True)
    for name in ('app', 'scanners'):
        environment = destination/(name+'-env')
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment/'Scripts/python.exe'
        subprocess.run([str(python), '-I', '-m', 'pip', 'install', '--no-index', '--only-binary=:all:',
                        '--find-links', str(bundle/('wheels-'+name)), '--requirement', str(bundle/(name+'.lock.txt'))], check=True)
    python = destination/'app-env/Scripts/python.exe'
    subprocess.run([str(python), '-I', '-m', 'pip', 'install', '--no-index', '--no-deps',
                    str(bundle/'localguard_audit-0.1.0-py3-none-any.whl')], check=True)
    shutil.copytree(bundle/'bin', destination/'bin')
    shutil.copytree(bundle/'grype-db', destination/'grype-db')
    binaries = {name: str(next((destination/'bin'/name).rglob(name+'.exe'))) for name in ('gitleaks','grype','gosec','cppcheck')}
    binaries.update({name:str(destination/'scanners-env'/'Scripts'/(name+'.exe')) for name in ('semgrep','pip-audit')})
    config = {'allowed_roots':roots, 'data_dir':str(destination/'state'), 'offline':True,
              'model_tier':'8gb' if model else '4gb', 'keep_model_resident':False,
              'model_endpoint':'http://127.0.0.1:17865/v1', 'model_name':'qwen3.5-4b',
              'model_path':model, 'model_binary':binary, 'model_library_dirs':libraries,
              'mmproj_path':projector, 'binaries':binaries, 'port':8765}
    config_path = destination/'localguard.json'
    config_path.write_text(json.dumps(config,ensure_ascii=False,indent=2),encoding='utf-8')
    for name, command in [('start-ui.cmd','ui'),('start-mcp.cmd','mcp'),('doctor.cmd','doctor')]:
        content = '@echo off\r\nset "GRYPE_DB_CACHE_DIR=%~dp0grype-db"\r\nset "PYTHONIOENCODING=utf-8"\r\n"%~dp0app-env\\Scripts\\python.exe" -m localguard --config "%~dp0localguard.json" '+command+'\r\n'
        (destination/name).write_bytes(content.encode('utf-8'))
    client = {'mcpServers':{'localguard':{'command':str(python), 'args':['-m','localguard','--config',str(config_path),'mcp'],
                                       'env':{'GRYPE_DB_CACHE_DIR':str(destination/'grype-db'),'PYTHONIOENCODING':'utf-8'}}}}
    (destination/'mcp-client.json').write_text(json.dumps(client,ensure_ascii=False,indent=2),encoding='utf-8')
    subprocess.run([str(python), '-I', '-m', 'pip', 'check'],check=True)
    subprocess.run([str(python), '-m', 'localguard','--config',str(config_path),'doctor'],check=True)
    print(json.dumps({'installed':str(destination),'ui_launcher':str(destination/'start-ui.cmd'),
                      'mcp_config':str(destination/'mcp-client.json'),'network_used':False},ensure_ascii=True,indent=2))


if __name__ == '__main__':
    main()
