"""Rebuild historical false positives — v2, quality-filtered.

v1 (rebuild_old_fp.py) used the LIVE working tree and the whole LocalGuard
root, so it swept in unrelated repos/ projects and produced findings that
were not the historical false positives at all. This v2 fixes all of that:

  1. FIXED CODE SNAPSHOT — LocalGuard fixes are scanned from git archive of
     the parent commit; the blog fix is scanned from its pinned HEAD (checked
     clean). No live working tree, no repos/ recursion.
  2. RULE-ID FILTER — only findings whose semgrep check_id is one of the rule
     IDs actually changed by that fix commit are kept.
  3. FULL PROVENANCE — code commit, rule parent, changed rule ids, per-file
     sha256, and the RAW semgrep JSON are all saved.
  4. EXPLICIT status — reproduced findings are candidates (needs_review),
     never pre-labelled.

The rule packs are loaded from a temporary file passed directly to semgrep,
so the live localguard/rules/ directory is never modified.

Usage:
  python scripts/rebuild_fp_v2.py --fix 852ed77 --out .workbuddy/gold/fp_v2_852ed77.json
  python scripts/rebuild_fp_v2.py --fix bfc9807 --out .workbuddy/gold/fp_v2_bfc9807.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

RULES_PATH = 'localguard/rules/security-extended.json'
FIXES = {
    '852ed77': {
        'parent': '7839507',
        'rule_ids': ['lg.ext.django-sql-injection-format-string',
                     'lg.ext.python-request-to-path-traversal',
                     'lg.ext.weak-crypto-random'],
        'target_kind': 'blog',
        'target_rel': 'repos/StarryFirefly-s-Blog-personal',
    },
    'bfc9807': {
        'parent': '4797d6a',
        'rule_ids': ['lg.ext.weak-crypto-sha1', 'lg.ext.xxe-xml-etree'],
        'target_kind': 'localguard_parent',
    },
    '4797d6a': {
        'parent': '904646c',
        'rule_ids': ['lg.ext.path-traversal-pathlib', 'lg.ext.ssrf-aiohttp-user-input'],
        'target_kind': 'localguard_parent',
        'known_broken': 'parent rule pack has 8 semgrep syntax errors; fail-closed gate rejects it',
    },
}


def git_show(rev: str, path: str) -> bytes:
    return subprocess.check_output(['git', 'show', f'{rev}:{path}'], cwd=ROOT)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def prepare_target(spec: dict, scratch: Path) -> tuple[Path, str, str]:
    """Return (target_dir, code_commit, code_kind)."""
    if spec['target_kind'] == 'blog':
        target = (ROOT / spec['target_rel']).resolve()
        status = subprocess.check_output(['git', '-C', str(target), 'status', '--porcelain'])
        if status.strip():
            raise RuntimeError('blog checkout is dirty; pin a clean commit first')
        commit = subprocess.check_output(['git', '-C', str(target), 'rev-parse', 'HEAD']).decode().strip()
        return target, commit, 'blog_pinned_head'
    # LocalGuard itself: git archive of the parent commit (no repos/ inside)
    commit = spec['parent']
    target = scratch / 'snapshot'
    target.mkdir()
    archive = subprocess.check_output(['git', 'archive', commit], cwd=ROOT)
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        try:/n            tar.extractall(target, filter="data")
        except TypeError:  # Python < 3.12
            tar.extractall(target)
    return target, commit, 'localguard_parent_archive'


def run_semgrep(target: Path, rule_file: Path, scratch: Path) -> dict:
    binary = json.loads((ROOT / 'localguard.local.json').read_text(encoding='utf-8'))['binaries']['semgrep']
    out = scratch / 'semgrep_raw.json'
    cmd = [binary, 'scan',
           '--config', str(ROOT / 'localguard/rules/backdoor.json'),
           '--config', str(ROOT / 'localguard/rules/security.json'),
           '--config', str(rule_file),
           '--json', '--quiet', '--oss-only', '--metrics=off',
           '--disable-version-check', '--disable-nosem', '--no-git-ignore',
           '--no-rewrite-rule-ids', '--jobs=1', '--max-target-bytes', '2000000',
           str(target)]
    with out.open('wb') as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.DEVNULL, timeout=300)
    return json.loads(out.read_text(encoding='utf-8'))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fix', choices=FIXES, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    spec = FIXES[a.fix]
    if spec.get('known_broken'):
        print(f'SKIP {a.fix}: {spec["known_broken"]}')
        return 0
    with tempfile.TemporaryDirectory(prefix='lg-fp-v2-') as td:
        scratch = Path(td)
        target, code_commit, code_kind = prepare_target(spec, scratch)
        rule_file = scratch / 'old-extended.json'
        old_bytes = git_show(spec['parent'], RULES_PATH).replace(b'\r\n', b'\n')
        rule_file.write_bytes(old_bytes)
        raw = run_semgrep(target, rule_file, scratch)
        errors = raw.get('errors', [])
        results = raw.get('results', [])
        kept = []
        for r in results:
            if r.get('check_id') not in spec['rule_ids']:
                continue
            path = Path(r.get('path', ''))
            abs_path = path if path.is_absolute() else target / path
            try:
                file_hash = sha256(abs_path.read_bytes())
            except OSError:
                file_hash = None
            kept.append({
                'rule_id': r['check_id'],
                'path': r.get('path'),
                'start_line': r['start']['line'],
                'end_line': r['end']['line'],
                'message': r['extra'].get('message'),
                'severity': r['extra'].get('severity'),
                'fingerprint': r['extra'].get('fingerprint'),
                'code_lines': r['extra'].get('lines'),
                'file_sha256': file_hash,
            })
        result = {
            'kind': 'old_rule_fp_reproduction_v2',
            'fix_commit': a.fix,
            'code_commit': code_commit,
            'code_kind': code_kind,
            'rule_parent': spec['parent'],
            'rule_sha256': sha256(old_bytes),
            'filtered_rule_ids': spec['rule_ids'],
            'semgrep_errors': len(errors),
            'semgrep_total_results': len(results),
            'kept_findings': len(kept),
            'note': ('Findings from a FIXED code snapshot with the pre-fix rule pack, '
                     'filtered to only the rule ids changed by this fix. Each needs human '
                     'confirmation as a genuine false positive; not pre-labelled.'),
            'findings': kept,
        }
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        # Keep the untouched semgrep JSON as the audit-grade raw evidence.
        raw_path = a.out.with_name(a.out.stem + '_semgrep_raw.json')
        raw_path.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'{a.fix}: semgrep results={len(results)} errors={len(errors)} '
          f'filtered_kept={len(kept)} -> {a.out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
