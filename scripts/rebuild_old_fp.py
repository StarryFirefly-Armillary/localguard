"""Reproduce historical FALSE-POSITIVE findings with the pre-fix rule packs.

The three rule fixes (4797d6a SSRF/path, bfc9807 SHA-1/XXE, 852ed77 random/SQL/
path) only changed localguard/rules/security-extended.json plus test asserts —
they did NOT save the original scanner findings. That means the historical
false positives cannot be reconstructed from tests alone (that would produce
hand-written samples inconsistent with production input).

This script re-runs a real LocalGuard audit with the PRE-FIX rule pack on a
fixed code snapshot and saves the raw production-shape findings as JSON. Only
findings that actually reproduce are usable as triage hard-negative gold
candidates; anything that cannot be reproduced stays a historical lead.

SAFETY: the scanner loads rules from a fixed path (RULE_DIR). To use an old
pack we temporarily replace that file with a byte-exact backup and restore it
in a finally block, verifying the restore by hash. The script refuses to run
if the working-tree rule file differs from git HEAD (other than CRLF).

Usage:
  python scripts/rebuild_old_fp.py --fix 4797d6a --target . --out .workbuddy/gold/fp_4797d6a.json
  python scripts/rebuild_old_fp.py --fix 852ed77 --target repos/StarryFirefly-s-Blog-personal \
      --out .workbuddy/gold/fp_852ed77_blog.json
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from bench_detection import run_audit

RULES = ROOT / 'localguard' / 'rules' / 'security-extended.json'

# fix commit -> the parent that holds the pre-fix rule pack
FIX_PARENTS = {
    '4797d6a': '904646c',  # SSRF / path traversal
    'bfc9807': '4797d6a',  # SHA-1 / XXE (parent already has 4797d6a fixes)
    '852ed77': '7839507',  # random / SQL / path (parent has both above)
}


def git_bytes(rev: str, path: str) -> bytes:
    rel = str(Path(path).relative_to(ROOT)).replace('\\', '/')
    return subprocess.check_output(['git', 'show', f'{rev}:{rel}'], cwd=ROOT)


def normalise(b: bytes) -> bytes:
    return b.replace(b'\r\n', b'\n')


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def assert_clean_baseline() -> None:
    """Refuse to touch a rule file that has real (non-EOL) local edits."""
    head = git_bytes('HEAD', str(RULES))
    local = RULES.read_bytes()
    if normalise(head) != normalise(local):
        raise RuntimeError('rules/security-extended.json has local edits; abort to avoid overwriting them')


async def audit_with_rules(target: Path, config: Path, old: bytes) -> dict:
    original = RULES.read_bytes()
    original_sha = sha(original)
    try:
        RULES.write_bytes(old)
        return await run_audit(target, config)
    finally:
        RULES.write_bytes(original)
        restored = RULES.read_bytes()
        if sha(restored) != original_sha:
            # Last-resort recovery from git if byte-exact restore failed.
            RULES.write_bytes(git_bytes('HEAD', str(RULES)))
            raise RuntimeError('rule file restore failed; recovered from git HEAD')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fix', choices=FIX_PARENTS, required=True)
    p.add_argument('--target', type=Path, required=True, help='fixed code snapshot to scan')
    p.add_argument('--config', type=Path, default=ROOT / 'localguard.local.json')
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    assert_clean_baseline()
    parent = FIX_PARENTS[a.fix]
    old = git_bytes(parent, str(RULES))
    old_normalised = normalise(old).decode('utf-8')
    rules = json.loads(old_normalised)
    print(f'reproducing {a.fix} with parent {parent} rules ({len(rules.get("rules", []))} rules)')
    data = asyncio.run(audit_with_rules(a.target.resolve(), a.config, old))
    coverage = data.get('coverage', {}).get('scanners', {})
    reproduced = coverage.get('semgrep') == 'completed'
    note = ('RAW findings with pre-fix rules; each needs human confirmation as a true false positive.'
            if reproduced else
            'REPRODUCTION FAILED: semgrep status != completed (old rule pack has syntax errors '
            'that the fail-closed scanner gate rejects). Findings below are unrelated scanner '
            'output, NOT reproduced historical false positives — do NOT use them as gold candidates. '
            'Per the collection principle, keep this only as a historical lead.')
    result = {
        'kind': 'old_rule_false_positive_reproduction',
        'fix_commit': a.fix,
        'rule_parent': parent,
        'target': str(a.target.resolve()),
        'scanner_coverage': coverage,
        'reproduced': reproduced,
        'raw_issues': data.get('issues', []),
        'note': note,
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    # verify rules restored byte-exact
    assert normalise(RULES.read_bytes()) == normalise(git_bytes('HEAD', str(RULES))), 'rule restore check failed'
    print(f'findings={len(result["raw_issues"])} written {a.out}; rules restored OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
