"""Collect real scanner findings from local repositories for training review.

This is a candidate collector, not a labeler. It preserves the production issue
shape plus raw scanner evidence, pinned code commit, file hash, window context,
and a bounded full-function code-only context. AI/human labels are added later.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from evidence_context import build_evidence
from localguard.config import Config
from localguard.registry import ToolRegistry

DATA = ROOT / '.workbuddy' / 'training_data'
LANGUAGES = {
    '.py': 'python', '.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript',
    '.tsx': 'typescript', '.go': 'go', '.rb': 'ruby', '.java': 'java', '.c': 'c',
    '.h': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.hpp': 'cpp', '.php': 'php',
    '.rs': 'rust', '.sol': 'solidity', '.sh': 'bash', '.ps1': 'powershell',
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_output(target: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(target), *args], text=True, encoding='utf-8').strip()


def repo_info(target: Path) -> dict:
    try:
        remote = git_output(target, 'remote', 'get-url', 'origin')
    except subprocess.CalledProcessError:
        remote = ''
    try:
        commit = git_output(target, 'rev-parse', 'HEAD')
    except subprocess.CalledProcessError as exc:
        raise ValueError(f'Target is not a Git checkout: {target}') from exc
    dirty = git_output(target, 'status', '--porcelain')
    if dirty:
        raise ValueError(f'Target checkout is dirty: {target}')
    return {'repo_url': remote, 'code_commit': commit, 'target': str(target.resolve())}


def load_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def raw_index(scanner: str, raw_ref: str, raw) -> tuple[str | None, str | None]:
    try:
        if scanner == 'semgrep':
            index = int(raw_ref.rsplit('/', 1)[1])
            result = raw['results'][index]
            return result.get('check_id'), result.get('extra', {}).get('message')
        if scanner == 'patterns':
            index = int(raw_ref.rsplit('/', 1)[1])
            result = raw['matches'][index]
            return result.get('rule_id'), None
        if scanner == 'gitleaks':
            index = int(raw_ref.rsplit('/', 1)[1])
            item = raw[index] if isinstance(raw, list) else raw.get('findings', [])[index]
            return item.get('RuleID') or item.get('rule_id'), item.get('Description') or item.get('description')
    except (ValueError, IndexError, KeyError, TypeError):
        pass
    return None, None


def source_context(target: Path, relative: str, line: int, language: str) -> tuple[list[dict], list[dict], str]:
    path = target / relative
    data = path.read_bytes()
    text = data.decode('utf-8', errors='replace')
    lines = text.splitlines()
    start, end = max(1, line - 3), min(len(lines), line + 3)
    window = [{'line': n, 'text': lines[n - 1][:100]} for n in range(start, end + 1)]
    try:
        full = [item for item in build_evidence(text, line, language, max_chars=1200) if item['text'].strip()]
    except Exception:
        full = window
    return window, full, sha256_bytes(data)


def candidate_from_issue(target: Path, issue: dict, audit_id: str, repo: dict, evidence_dir: Path) -> dict:
    location = issue['locations'][0]
    relative = location['path'].replace('\\', '/')
    line = int(location['line'])
    language = LANGUAGES.get(Path(relative).suffix.lower(), 'unknown')
    evidence = issue.get('evidence', [])
    scanner = next((e.get('tool') for e in evidence if e.get('tool') in {'patterns', 'semgrep', 'gitleaks'}), '')
    raw_ref = next((e.get('raw_ref') for e in evidence if e.get('tool') == scanner), '')
    raw_path = evidence_dir / f'{scanner}.json' if scanner else None
    raw = load_json(raw_path) if raw_path and raw_path.is_file() else None
    if isinstance(raw, dict) and isinstance(raw.get('raw'), dict):
        raw = raw['raw']
    rule_id, raw_message = raw_index(scanner, raw_ref, raw) if raw is not None else (None, None)
    window, full, file_hash = source_context(target, relative, line, language)
    identity = '|'.join([repo['code_commit'], scanner, rule_id or raw_ref, relative, str(line), issue.get('title', '')])
    return {
        'id': 'FINDING-' + hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16],
        'source': 'current_scanner',
        'proposed_label': None,
        'human_label': None,
        'ai_label': None,
        'needs_review': True,
        'provenance': {
            **repo,
            'audit_id': audit_id,
            'scanner': scanner,
            'rule_id': rule_id,
            'raw_ref': raw_ref,
            'raw_evidence': str(raw_path.relative_to(ROOT)) if raw_path and raw_path.is_file() else None,
            'raw_evidence_sha256': sha256_bytes(raw_path.read_bytes()) if raw_path and raw_path.is_file() else None,
            'file_sha256': file_hash,
        },
        'finding': {
            'title': issue.get('title'),
            'severity': issue.get('severity'),
            'category': issue.get('category'),
            'cwe': issue.get('cwe', ''),
            'confidence': issue.get('confidence'),
            'rule_id': rule_id,
            'path': relative,
            'line': line,
            'evidence': evidence,
            'source_window': window,
            'source_full_code_only': full,
            'raw_message': raw_message,
        },
    }


async def collect_target(target: Path, state_root: Path) -> tuple[list[dict], dict]:
    target = target.resolve(strict=True)
    repo = repo_info(target)
    slug = re.sub(r'[^A-Za-z0-9_.-]+', '-', target.name).strip('-') or 'repo'
    data_dir = state_root / slug
    base = Config.load(str(ROOT / 'localguard.local.json'))
    config = Config(
        allowed_roots=[target], data_dir=data_dir, offline=True,
        model_tier='rules', binaries=base.binaries, scanner_timeout=base.scanner_timeout,
        max_files=base.max_files, max_file_bytes=base.max_file_bytes,
        max_repo_bytes=base.max_repo_bytes,
    )
    registry = ToolRegistry(config)
    try:
        queued = await registry.call('audit_repository', {
            'target': str(target), 'scanners': ['patterns', 'semgrep', 'gitleaks'],
            'include_dependencies': False, 'model_tier': 'rules', 'auto_exclude': True,
        }, f'collect-{slug}', 'training-collector')
        if queued.get('isError'):
            raise ValueError(queued.get('error', 'audit submission failed'))
        audit_id = queued['data']['audit_id']
        issues = []
        offset = 0
        while True:
            status = await registry.call('get_audit_status', {
                'audit_id': audit_id, 'wait_seconds': 2, 'offset': offset, 'limit': 200,
            }, f'collect-{slug}', 'training-collector')
            if status.get('isError'):
                raise ValueError(status.get('error', 'status failed'))
            data = status['data']
            if data['status'] in {'completed', 'failed', 'cancelled'}:
                if data['status'] != 'completed':
                    raise ValueError(f'audit {audit_id} ended {data["status"]}: {data.get("error")}')
                issues.extend(data.get('issues', []))
                next_offset = data.get('next_offset')
                if next_offset is None or next_offset <= offset:
                    break
                offset = next_offset
                continue
            await asyncio.sleep(0.2)
        evidence_dir = data_dir / 'evidence' / audit_id
        candidates = [candidate_from_issue(target, issue, audit_id, repo, evidence_dir) for issue in issues]
        summary = {
            **repo,
            'audit_id': audit_id,
            'findings': len(candidates),
            'scanners': data.get('coverage', {}).get('scanners', {}),
            'severity': dict(Counter(c['finding']['severity'] for c in candidates)),
            'rules': dict(Counter(c['provenance'].get('rule_id') or c['provenance']['scanner'] for c in candidates)),
            'warnings': data.get('warnings', []),
        }
        return candidates, summary
    finally:
        await registry.close()


async def run(targets: list[Path], out: Path) -> dict:
    state_root = DATA / 'state'
    state_root.mkdir(parents=True, exist_ok=True)
    all_candidates = []
    summaries = []
    for target in targets:
        print(f'collecting {target}', flush=True)
        candidates, summary = await collect_target(target, state_root)
        all_candidates.extend(candidates)
        summaries.append(summary)
        print(json.dumps({'target': str(target), 'findings': len(candidates), 'scanners': summary['scanners']}, ensure_ascii=False), flush=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(''.join(json.dumps(c, ensure_ascii=False) + '\n' for c in all_candidates), encoding='utf-8')
    manifest = {
        'kind': 'real_scanner_finding_candidates',
        'targets': summaries,
        'total_findings': len(all_candidates),
        'unique_ids': len({c['id'] for c in all_candidates}),
        'label_status': 'unlabelled',
        'note': 'Candidates only. No AI or human labels have been assigned.',
    }
    out.with_name(out.stem + '_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'output': str(out), 'total_findings': len(all_candidates), 'unique_ids': manifest['unique_ids']}, ensure_ascii=False))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, action='append', required=True)
    parser.add_argument('--out', type=Path, default=DATA / 'local_findings.jsonl')
    args = parser.parse_args()
    asyncio.run(run(args.target, args.out))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
