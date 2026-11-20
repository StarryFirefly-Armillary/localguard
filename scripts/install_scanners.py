from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

ARTIFACTS = {
    'gitleaks':('gitleaks_8.30.1_windows_x64.zip','d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e'),
    'grype':('grype_0.122.1_windows_amd64.zip','24e19d6378782d2da343b80c632e342bcdd3bd1bf44e415a0ff81cf85ce1043a'),
    'gosec':('gosec_2.30.0_windows_amd64.tar.gz','503bdfe6155584f2497ef855846b66406bce5b574ce1a9c7a7bb171aff2caa02'),
    'cppcheck':('cppcheck-2.22.0-x64-Setup.msi','3929162bab7e71d1b9b18708ec054fb0188bfc8ea1660979ed95837f5a9f547b')
}


def main():
    parser = argparse.ArgumentParser(description='Verify pinned official downloads and extract local scanner binaries')
    parser.add_argument('--downloads',type=Path,default=Path('.localguard/downloads'))
    parser.add_argument('--destination',type=Path,default=Path('.localguard/bin'))
    parser.add_argument('--scanners',nargs='+',choices=list(ARTIFACTS),default=['gitleaks','grype','gosec'])
    args = parser.parse_args()
    args.destination.mkdir(parents=True,exist_ok=True)
    installed = {}
    for name in args.scanners:
        filename,digest = ARTIFACTS[name]
        artifact = args.downloads / filename
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != digest:
            raise SystemExit(f'Integrity check failed: {filename}')
        destination = args.destination / name
        destination.mkdir(exist_ok=True)
        if filename.endswith('.zip'):
            with zipfile.ZipFile(artifact) as archive:
                for entry in archive.infolist():
                    if Path(entry.filename).name in (name+'.exe','LICENSE','LICENSE.txt'):
                        (destination / Path(entry.filename).name).write_bytes(archive.read(entry))
        elif filename.endswith('.tar.gz'):
            with tarfile.open(artifact) as archive:
                for entry in archive.getmembers():
                    if entry.isfile() and Path(entry.name).name in (name+'.exe','LICENSE','LICENSE.txt'):
                        with archive.extractfile(entry) as stream:
                            (destination / Path(entry.name).name).write_bytes(stream.read())
        else:
            result = subprocess.run(['msiexec.exe','/a',str(artifact.resolve()),'/qn',
                                     'TARGETDIR='+str(destination.resolve())],timeout=120,check=False)
            if result.returncode not in (0,3010):
                raise SystemExit(f'Administrative MSI extraction failed: {result.returncode}')
        binary = next(destination.rglob(name+'.exe'),None)
        if not binary:
            raise SystemExit(f'Executable not found after extraction: {name}')
        installed[name] = str(binary.resolve())
    print(json.dumps(installed,indent=2))


if __name__=='__main__':
    main()
