"""Collect pinned vulnerable/fixed function pairs from BigVul and Vul4J.

Only Git plumbing and tree-sitter parsing are used. Upstream code is never
checked out into a working tree, compiled, or executed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys_path = ROOT
import sys
sys.path.insert(0, str(sys_path))

from localguard.lines import source_lines
from localguard.parser import SourceParser

DATA = ROOT / '.workbuddy' / 'training_data' / 'external'
REPOS = DATA / 'repos'
HEX = re.compile(r'^[0-9a-f]{40}$')
HUNK = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(repo: Path, *args: str) -> bytes:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('GIT_'):
            del env[key]
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1')
    return subprocess.check_output(['git', '-C', str(repo), *args], env=env, stderr=subprocess.PIPE)


def repo_from_commit(url: str) -> tuple[str, str]:
    parts = urlsplit(url).path.strip('/').split('/')
    if len(parts) < 4 or parts[2] != 'commit':
        raise ValueError(f'Not a GitHub commit URL: {url}')
    owner, name, commit = parts[0], parts[1], parts[3]
    if not HEX.fullmatch(commit):
        raise ValueError(f'Commit is not a full SHA-1: {url}')
    return f'https://github.com/{owner}/{name}.git', commit


def ensure_repo(url: str, commit: str, slug: str) -> Path:
    REPOS.mkdir(parents=True, exist_ok=True)
    destination = REPOS / slug
    if destination.exists():
        try:
            git(destination, 'cat-file', '-e', f'{commit}^{{commit}}')
            return destination
        except subprocess.CalledProcessError:
            subprocess.run([
                'git', '-C', str(destination), 'fetch', '--depth=2', 'origin', commit,
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
            return destination
    subprocess.run([
        'git', 'clone', '--bare', '--no-checkout', '--template=', '--depth=2',
        '--no-tags', f'--revision={commit}', url, str(destination),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
    return destination


def changed_lines(repo: Path, parent: str, fix: str, path: str) -> tuple[set[int], set[int]]:
    raw = git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--unified=0', parent, fix, '--', path)
    before, after = set(), set()
    old = new = None
    for line in raw.decode('utf-8', errors='replace').splitlines():
        match = HUNK.match(line)
        if match:
            old = int(match.group(1))
            new = int(match.group(3))
            continue
        if old is None or new is None:
            continue
        if line.startswith('-') and not line.startswith('---'):
            before.add(old)
            old += 1
        elif line.startswith('+') and not line.startswith('+++'):
            after.add(new)
            new += 1
        elif line.startswith(' '):
            old += 1
            new += 1
    return before, after


def node_name(node, data: bytes) -> str:
    current = node.child_by_field_name('name') or node.child_by_field_name('declarator')
    stack = [current] if current else []
    while stack:
        candidate = stack.pop(0)
        if candidate is None:
            continue
        if candidate.type in {'identifier', 'field_identifier', 'type_identifier'}:
            return data[candidate.start_byte:candidate.end_byte].decode('utf-8', errors='replace')
        stack.extend(candidate.children)
    return ''


def functions(path: Path, data: bytes, changed: set[int]) -> list[dict]:
    parser = SourceParser()
    language, tree = parser.source(path, data)
    if not tree or tree.root_node.has_error:
        return []
    lines = source_lines(data)
    found = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if ('function' in node.type or 'method' in node.type):
            start, end = node.start_point.row + 1, node.end_point.row + 1
            name = node_name(node, data)
            if name and any(start <= line <= end for line in changed):
                found.append({
                    'name': name, 'start_line': start, 'end_line': end,
                    'code': '\n'.join(lines[start - 1:end]),
                })
        stack.extend(reversed(node.children))
    return found


def blob_hash(repo: Path, revision: str, path: str) -> tuple[str, str]:
    blob = git(repo, 'rev-parse', f'{revision}:{path}').decode().strip()
    raw = git(repo, 'cat-file', 'blob', blob)
    return blob, sha(raw)


def extract_pair(repo: Path, parent: str, fix: str, path: str) -> list[dict]:
    before_raw = git(repo, 'show', f'{parent}:{path}')
    after_raw = git(repo, 'show', f'{fix}:{path}')
    before_lines, after_lines = changed_lines(repo, parent, fix, path)
    before = functions(Path(path), before_raw, before_lines)
    after = functions(Path(path), after_raw, after_lines)
    after_by_name = {f['name']: f for f in after}
    before_blob, before_file_hash = blob_hash(repo, parent, path)
    after_blob, after_file_hash = blob_hash(repo, fix, path)
    pairs = []
    for vulnerable in before:
        fixed = after_by_name.get(vulnerable['name'])
        if not fixed:
            continue
        if vulnerable['end_line'] <= vulnerable['start_line'] or fixed['end_line'] <= fixed['start_line']:
            continue
        if '{' not in fixed['code'] or vulnerable['code'] == fixed['code']:
            continue
        pairs.append({
            'path': path,
            'function': vulnerable['name'],
            'vulnerable': vulnerable,
            'fixed': fixed,
            'before_git_blob': before_blob,
            'after_git_blob': after_blob,
            'before_file_sha256': before_file_hash,
            'after_file_sha256': after_file_hash,
            'vulnerable_code_sha256': sha(vulnerable['code'].encode('utf-8')),
            'fixed_code_sha256': sha(fixed['code'].encode('utf-8')),
        })
    return pairs


def select_bigvul(limit: int) -> list[dict]:
    csv.field_size_limit(20_000_000)
    rows = list(csv.DictReader((DATA / 'bigvul.csv').open(encoding='utf-8', errors='replace', newline='')))
    blocked = {'Chrome', 'linux', 'Android', 'FFmpeg', 'curl', 'php-src'}
    seen, selected = set(), []
    for row in rows:
        if row['project'] in blocked or not row['cwe_id'] or not HEX.fullmatch(row['commit_id']):
            continue
        if not row['version_before_fix'] or not HEX.fullmatch(row['version_before_fix']):
            continue
        try:
            url, commit = repo_from_commit(row['ref_link'])
        except ValueError:
            continue
        if commit != row['commit_id']:
            continue
        key = (row['project'], row['cwe_id'])
        if key in seen:
            continue
        seen.add(key)
        selected.append({
            'dataset': 'BigVul', 'dataset_license': 'MIT', 'cve': row['cve_id'],
            'cwe': row['cwe_id'], 'repo_url': url, 'fix_commit': commit,
            'parent_commit': row['version_before_fix'], 'project': row['project'],
            'language': row['lang'], 'summary': row.get('summary', ''),
            'source_row_sha256': sha(json.dumps(row, sort_keys=True, ensure_ascii=False).encode('utf-8')),
        })
        if len(selected) >= limit:
            break
    return selected


def select_vul4j(limit: int) -> list[dict]:
    rows = list(csv.DictReader((DATA / 'vul4j.csv').open(encoding='utf-8', newline='')))
    seen, selected = set(), []
    for row in rows:
        if not row['human_patch'] or '/compare/' in row['human_patch']:
            continue
        try:
            url, commit = repo_from_commit(row['human_patch'])
        except ValueError:
            continue
        owner_repo = '/'.join(urlsplit(url).path.strip('/').split('/')[:2]).removesuffix('.git')
        if owner_repo.lower() != row['repo_slug'].lower():
            continue
        cwe = row['cwe_id'] if row['cwe_id'].startswith('CWE-') else ''
        key = (row['repo_slug'], cwe)
        if key in seen:
            continue
        seen.add(key)
        selected.append({
            'dataset': 'Vul4J', 'dataset_license': 'CC-BY-4.0', 'cve': row['cve_id'],
            'cwe': cwe, 'repo_url': url, 'fix_commit': commit,
            'parent_commit': None, 'project': row['repo_slug'], 'language': 'Java',
            'summary': row.get('cwe_name', ''), 'vul_id': row['vul_id'],
            'source_row_sha256': sha(json.dumps(row, sort_keys=True, ensure_ascii=False).encode('utf-8')),
        })
        if len(selected) >= limit:
            break
    return selected


def collect(item: dict) -> tuple[list[dict], dict]:
    slug = re.sub(r'[^A-Za-z0-9_.-]+', '-', item['project']).strip('-')
    repo = ensure_repo(item['repo_url'], item['fix_commit'], slug)
    fix = git(repo, 'rev-parse', item['fix_commit']).decode().strip()
    parent = item['parent_commit'] or git(repo, 'rev-parse', f'{fix}^').decode().strip()
    files = git(repo, 'diff', '--name-only', parent, fix).decode('utf-8', errors='replace').splitlines()
    pairs = []
    for path in files:
        if Path(path).suffix.lower() not in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.java'}:
            continue
        try:
            pairs.extend(extract_pair(repo, parent, fix, path))
        except (ValueError, UnicodeError, subprocess.CalledProcessError):
            continue
    records = []
    for index, pair in enumerate(pairs, 1):
        records.append({
            'id': f"{item['dataset']}:{item.get('vul_id') or item['cve']}:{index}",
            'sample_kind': 'cve_function_pair',
            'source': item['dataset'].lower(),
            'needs_review': True,
            'human_label': None,
            'provenance': {**item, 'parent_commit': parent, 'resolved_fix_commit': fix},
            **pair,
        })
    return records, {'item': item, 'resolved_parent': parent, 'files_changed': len(files), 'pairs': len(records)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', choices=['bigvul', 'vul4j', 'both'], default='both')
    parser.add_argument('--limit-each', type=int, default=20)
    parser.add_argument('--out', type=Path, default=DATA / 'cve_function_pairs.jsonl')
    args = parser.parse_args()
    items = []
    if args.dataset in {'bigvul', 'both'}:
        items.extend(select_bigvul(args.limit_each))
    if args.dataset in {'vul4j', 'both'}:
        items.extend(select_vul4j(args.limit_each))
    records, summaries = [], []
    for item in items:
        print(f"collecting {item['dataset']} {item.get('vul_id') or item['cve']} {item['project']}", flush=True)
        try:
            found, summary = collect(item)
        except Exception as exc:
            summaries.append({'item': item, 'error': f'{type(exc).__name__}: {exc}'})
            print(f'  failed: {type(exc).__name__}: {exc}', flush=True)
            continue
        records.extend(found)
        summaries.append(summary)
        print(f"  pairs={len(found)}", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records), encoding='utf-8')
    manifest = {
        'kind': 'cve_function_pair_candidates',
        'datasets': items,
        'total_pairs': len(records),
        'by_dataset': {name: sum(1 for r in records if r['source'] == name) for name in ('bigvul', 'vul4j')},
        'summaries': summaries,
        'note': 'Pinned vulnerable/fixed function pairs; no upstream code executed. Human review still required.',
    }
    args.out.with_name(args.out.stem + '_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'output': str(args.out), 'pairs': len(records), 'by_dataset': manifest['by_dataset']}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
