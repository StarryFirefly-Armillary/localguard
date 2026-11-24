"""Build a Git corpus from pinned fixed files in collected CVE function pairs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / '.workbuddy' / 'training_data'
REPOS = DATA / 'external' / 'repos'


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.PIPE)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pairs', type=Path, default=DATA / 'external' / 'cve_function_pairs.jsonl')
    parser.add_argument('--out', type=Path, default=DATA / 'fixed_corpus')
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.pairs.read_text(encoding='utf-8').splitlines() if line.strip()]
    if args.out.exists():
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True)
    manifest = []
    seen = set()
    for row in rows:
        prov = row['provenance']
        key = (prov['repo_url'], prov['resolved_fix_commit'], row['path'])
        if key in seen:
            continue
        seen.add(key)
        slug = re.sub(r'[^A-Za-z0-9_.-]+', '-', prov['project']).strip('-')
        repo = REPOS / slug
        raw = git(repo, 'show', f"{prov['resolved_fix_commit']}:{row['path']}")
        relative = Path(slug) / row['path']
        destination = args.out / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        manifest.append({
            'corpus_path': relative.as_posix(),
            'project': prov['project'], 'repo_url': prov['repo_url'],
            'fix_commit': prov['resolved_fix_commit'], 'path': row['path'],
            'dataset': prov['dataset'], 'dataset_license': prov['dataset_license'],
            'cve': prov['cve'], 'cwe': prov['cwe'],
        })
    subprocess.run(['git', 'init', '-q', str(args.out)], check=True)
    subprocess.run(['git', '-C', str(args.out), 'add', '.'], check=True)
    subprocess.run([
        'git', '-C', str(args.out), '-c', 'user.name=LocalGuard Data Collector',
        '-c', 'user.email=collector@local.invalid', 'commit', '-q', '-m', 'Pinned fixed CVE source corpus',
    ], check=True)
    (args.out / 'corpus_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    subprocess.run(['git', '-C', str(args.out), 'add', 'corpus_manifest.json'], check=True)
    subprocess.run([
        'git', '-C', str(args.out), '-c', 'user.name=LocalGuard Data Collector',
        '-c', 'user.email=collector@local.invalid', 'commit', '-q', '-m', 'Add corpus provenance manifest',
    ], check=True)
    print(json.dumps({'corpus': str(args.out), 'files': len(manifest), 'commit': git(args.out, 'rev-parse', 'HEAD').decode().strip()}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
