"""Build the first small, trustworthy HUMAN REVIEW batch for the gold set.

Does NOT expand the candidate pool. It selects from already-filtered sources:

  A. tool_call.jsonl — 6 real-CVE findings, production triage input shape
  B. VulnShop function+CWE strict — 6 high-confidence positive findings
     (one per ground-truth vulnerability, commit pinned)
  C. VulnShop uncertain — a bounded slice (default 6) of file+CWE-only findings
  D. old-rule FP v2 — 3 SHA-1/XXE + 23 blog (grouped by random/path/SQL)

Every record carries: rule_id, code_commit, file_sha256, path/line, raw
scanner evidence ref, proposed_label, and EMPTY human_label/human_reason.
Nothing is pre-labelled; the old 75 polluted candidates stay frozen.

Output: .workbuddy/gold/review_batch_v0.jsonl (local data, gitignored).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from collect_gold_candidates import make_candidate  # reuse, not copy

GOLD = ROOT / '.workbuddy' / 'gold'
TOOL_CALL = ROOT / '.localguard' / 'curation' / 'tool_call.jsonl'


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding='utf-8').splitlines() if l.strip()]


def from_tool_call() -> list[dict]:
    out = []
    for row in load_jsonl(TOOL_CALL):
        for issue in row.get('issues', []):
            prov = row.get('provenance') or {}
            out.append(make_candidate(issue, 'real_cve_tool_call', {
                'cve': row.get('cve'),
                'upstream_revision': row.get('upstream_revision'),
                'provenance': prov,
            }, 'likely_true'))
    return out


def from_vulnshop(path: Path, limit_uncertain: int) -> tuple[list[dict], list[dict]]:
    rows = load_jsonl(path)
    strict, uncertain = [], []
    seen_gt = set()
    # one candidate per ground-truth vulnerability for strict layer
    for r in rows:
        p = r['provenance']
        if p.get('match_quality') not in ('function_cwe', 'strict_file_cwe_line'):
            continue
        gt = (p.get('ground_truth_ids') or [''])[0]
        if not gt or gt in seen_gt:
            continue
        seen_gt.add(gt)
        strict.append(r)
    # bounded uncertain slice
    for r in rows:
        if r['proposed_label'] != 'uncertain':
            continue
        if len(uncertain) >= limit_uncertain:
            break
        uncertain.append(r)
    return strict, uncertain


def from_fp_v2(path: Path) -> list[dict]:
    d = json.loads(path.read_text(encoding='utf-8'))
    out = []
    for f in d.get('findings', []):
        out.append({
            'id': f"{d['fix_commit']}:{f['rule_id']}:{f['path']}:{f['start_line']}",
            'source': 'old_rule_fp_v2',
            'proposed_label': 'likely_false',
            'needs_review': True,
            'human_label': None,
            'human_reason': None,
            'provenance': {
                'fix_commit': d['fix_commit'], 'code_commit': d['code_commit'],
                'rule_parent': d['rule_parent'], 'rule_ids': d['filtered_rule_ids'],
                'raw_semgrep': str(path.with_name(path.stem + '_semgrep_raw.json')),
            },
            'finding': {
                'rule_id': f['rule_id'], 'path': f['path'], 'line': f['start_line'],
                'severity': f['severity'], 'message': f['message'],
                'file_sha256': f['file_sha256'], 'code_lines': f['code_lines'],
                'fingerprint': f['fingerprint'],
                'raw_evidence_ref': f"semgrep#check_id={f['rule_id']}",
            },
        })
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--uncertain-limit', type=int, default=6)
    p.add_argument('--out', type=Path, default=GOLD / 'review_batch_v0.jsonl')
    a = p.parse_args()
    tc = from_tool_call()
    strict, uncertain = from_vulnshop(GOLD / 'pos_function_cwe.jsonl', a.uncertain_limit)
    fp_bfc = from_fp_v2(GOLD / 'fp_v2_bfc9807.json')
    fp_blog = from_fp_v2(GOLD / 'fp_v2_852ed77.json')
    batch = tc + strict + uncertain + fp_bfc + fp_blog
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in batch), encoding='utf-8')
    print(f'total={len(batch)}  tool_call={len(tc)}  strict={len(strict)}  '
          f'uncertain={len(uncertain)}  fp_bfc={len(fp_bfc)}  fp_blog={len(fp_blog)}')
    print(f'written {a.out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
