"""Collect task-aligned GOLD-SET CANDIDATES with full scanner findings.

Two sources, both produce raw production-shape findings (id/title/severity/
category/cwe/locations/evidence) rather than hand-written descriptions:

  pos  — run the CURRENT scanner on VulnShop, align outputs with the 16
         intentional vulnerabilities in benchmarks/vulnshop-ground-truth.json,
         keep findings that actually hit a documented real vulnerability.
         These are triage POSITIVE candidates (a real finding that a triage
         model should call likely_true).

  fp   — re-run scanner findings from a saved raw issues JSON via --replay
         (for old-rule false positives reproduced by scripts/rebuild_old_fp.py).
         These are triage NEGATIVE candidates (a scanner finding that is
         actually benign and should be likely_false).

Output is a JSONL of candidate records for HUMAN CONFIRMATION. Nothing here is
a label: every record carries proposed_label but also needs_review=true and
an empty human_label. This is DATA, not a report; it is written under
.workbuddy/gold/ (gitignored) until the user confirms the labels.

Usage:
  python scripts/collect_gold_candidates.py --pos --config localguard.local.json \
      --target repos/code-safety/vulnerable-app --out .workbuddy/gold/pos_candidates.jsonl
  python scripts/collect_gold_candidates.py --replay <raw_issues.json> --out .workbuddy/gold/fp_candidates.jsonl
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from bench_detection import run_audit, load_ground_truth, matches, DEFAULT_TARGET  # reuse, not copy


def make_candidate(issue: dict, source: str, provenance: dict, proposed_label: str) -> dict:
    """Normalise a production finding into a review-ready candidate record."""
    return {
        'id': issue.get('id'),
        'source': source,
        'proposed_label': proposed_label,   # suggestion only, NOT a gold label
        'needs_review': True,
        'human_label': None,                # filled by the user
        'human_reason': None,
        'provenance': provenance,
        'finding': {
            'title': issue.get('title'),
            'severity': issue.get('severity'),
            'category': issue.get('category'),
            'cwe': issue.get('cwe'),
            'confidence': issue.get('confidence'),
            'locations': issue.get('locations', []),
            'evidence': issue.get('evidence', []),
            'needs_human_review': issue.get('needs_human_review'),
        },
    }


def align_positives(data: dict) -> list[dict]:
    """Keep DISTINCT scanner findings that hit a documented real vulnerability.

    One issue can land on multiple documented vulnerabilities (e.g. a single
    semgrep finding at catalog/views.py:119 covers VULN-002 and VULN-003). A
    gold sample is one production finding, so de-duplicate by issue id and
    record all matched ground-truth ids as provenance — never emit the same
    finding twice, which would leak between train/eval splits.
    """
    vulns = load_ground_truth()
    issues = data.get('issues', [])
    matched: dict[str, list[dict]] = {}
    issue_by_id: dict[str, dict] = {}
    for vuln in vulns:
        for issue in issues:
            if any(matches(loc, vuln) for loc in issue.get('locations', [])):
                iid = issue.get('id')
                matched.setdefault(iid, []).append(vuln)
                issue_by_id.setdefault(iid, issue)
                break
    out = []
    for iid, hits in matched.items():
        out.append(make_candidate(issue_by_id[iid], 'vulnshop_current_scan', {
            'ground_truth_ids': [v['id'] for v in hits],
            'ground_truth_locations': [v['location'] for v in hits],
            'ground_truth_cwes': [v.get('cwe') for v in hits],
            'target': data.get('target'),
            'audit_id': data.get('audit_id'),
        }, 'likely_true'))
    return out


def replay_false_positives(raw: dict, provenance: dict) -> list[dict]:
    """Wrap reproduced old-rule findings as likely_false candidates."""
    # rebuild_old_fp.py writes raw_issues; a bare issues JSON also works.
    issues = raw.get('raw_issues', raw.get('issues', []))
    if not issues:
        raise ValueError('replay input has no raw_issues/issues to convert')
    return [
        make_candidate(issue, 'old_rule_replay', {
            **provenance,
            'raw_ref': issue.get('evidence', [{}])[0].get('raw_ref') if issue.get('evidence') else None,
        }, 'likely_false')
        for issue in issues
    ]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')


async def collect_pos(target: Path, config: Path) -> dict:
    data = await run_audit(target, config)
    # run_audit returns get_audit_status data; attach target for provenance.
    data['target'] = str(target)
    return {'issues': data.get('issues', []), 'target': str(target),
            'audit_id': data.get('audit_id'), 'coverage': data.get('coverage')}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pos', action='store_true', help='run current scanner on VulnShop')
    p.add_argument('--replay', type=Path, help='raw issues JSON from old-rule reproduction')
    p.add_argument('--target', type=Path, default=DEFAULT_TARGET)
    p.add_argument('--config', type=Path, default=ROOT / 'localguard.local.json')
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    if not (a.pos ^ bool(a.replay)):
        p.error('exactly one of --pos or --replay is required')
    if a.pos:
        data = asyncio.run(collect_pos(a.target.resolve(), a.config))
        rows = align_positives(data)
        print(f"scanner issues={len(data['issues'])}, positives aligned={len(rows)}")
    else:
        raw = json.loads(a.replay.read_text(encoding='utf-8'))
        prov = {'replay_file': str(a.replay)}
        if 'provenance' in raw:
            prov.update(raw['provenance'])
        rows = replay_false_positives(raw, prov)
        print(f"replayed findings={len(rows)}")
    write_jsonl(a.out, rows)
    print(f"written {a.out} ({len(rows)} candidates, all needs_review=true)")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
