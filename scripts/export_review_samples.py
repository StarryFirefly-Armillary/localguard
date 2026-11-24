"""Read-only export of human-reviewed findings (reviews + jobs.result).

Per review, no schema migration is needed: jobs.result already stores the full
report. This script joins reviews -> jobs.result, extracts the exact finding,
and writes a candidate record with the human decision as provenance.

Caveat recorded in output: the current two reviews are duplicate reviews of
ONE finding (same issue_id, same vulnerable.c fixture), with model_verdict
empty. They are ONE gold candidate, not two independent samples.

Output is DATA under .workbuddy/gold/ (gitignored), not a report.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / '.localguard' / 'state.sqlite3'


def export(db_path: Path) -> dict:
    db = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
    rows = db.execute('SELECT audit_id, issue_id, decision, rule_id, model_verdict FROM reviews').fetchall()
    by_issue: dict[str, dict] = {}
    duplicates = 0
    missing = 0
    for audit_id, issue_id, decision, rule_id, model_verdict in rows:
        job = db.execute('SELECT result FROM jobs WHERE id=?', (audit_id,)).fetchone()
        if not job or not job[0]:
            missing += 1
            continue
        report = json.loads(job[0])
        finding = next((i for i in report.get('issues', []) if i.get('id') == issue_id), None)
        if not finding:
            missing += 1
            continue
        if issue_id in by_issue:
            duplicates += 1
            by_issue[issue_id]['review_events'].append({
                'audit_id': audit_id, 'decision': decision,
                'rule_id': rule_id, 'model_verdict': model_verdict,
            })
            continue
        by_issue[issue_id] = {
            'id': issue_id,
            'source': 'human_review',
            'human_label': decision,
            'human_reason': None,
            'needs_review': True,
            'review_events': [{
                'audit_id': audit_id, 'decision': decision,
                'rule_id': rule_id, 'model_verdict': model_verdict,
            }],
            'provenance': {
                'target': report.get('target'),
                'root': report.get('root'),
                'audit_id': audit_id,
                'model_tier': report.get('model_tier'),
            },
            'finding': {
                'title': finding.get('title'), 'severity': finding.get('severity'),
                'category': finding.get('category'), 'cwe': finding.get('cwe'),
                'confidence': finding.get('confidence'),
                'locations': finding.get('locations', []),
                'evidence': finding.get('evidence', []),
            },
        }
    return {
        'kind': 'human_review_export',
        'review_rows': len(rows),
        'unique_findings': len(by_issue),
        'duplicate_review_events': duplicates,
        'unresolvable': missing,
        'note': ('Current reviews are duplicate reviews of ONE fixture finding (vulnerable.c), '
                 'model_verdict empty — one gold candidate, not independent samples. '
                 'model_verdict empty means the model triage verdict was not recorded; '
                 'do not infer model behaviour from these.'),
        'candidates': list(by_issue.values()),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    data = export(DB)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"reviews={data['review_rows']} unique_findings={data['unique_findings']} "
          f"duplicates={data['duplicate_review_events']} unresolvable={data['unresolvable']}")
    print(f"written {a.out}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
