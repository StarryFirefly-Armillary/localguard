"""READ-ONLY report of model_triage_abstained audit events.

Pure summarize() is unit-testable with mock events; load() opens SQLite in
read-only URI mode and never writes. No model startup, no DB writes.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRITICAL_CWE = {'CWE-78', 'CWE-89', 'CWE-502', 'CWE-611', 'CWE-918', 'CWE-22'}


def load(store_path: Path) -> list[dict]:
    con = sqlite3.connect(f'file:{store_path}?mode=ro', uri=True)
    try:
        out = []
        for (payload,) in con.execute('SELECT payload FROM logs'):
            try:
                event = json.loads(payload)
            except Exception:
                continue
            if event.get('event') == 'model_triage_abstained':
                out.append(event)
        return out
    finally:
        con.close()


def summarize(events: list[dict], total_triage: int | None = None) -> dict:
    by = lambda key: dict(Counter(str(e.get(key) or '') for e in events))
    evidence = [e.get('evidence_bytes') for e in events if isinstance(e.get('evidence_bytes'), (int, float))]
    critical = [e for e in events if e.get('cwe') in CRITICAL_CWE]
    # New logs carry repo_key (canonical) plus target; legacy-style logs may
    # only carry repo_url. Prefer canonical key, then URL, then raw target.
    def repo_name(e):
        return e.get('repo_key') or e.get('repo_url') or e.get('target') or ''
    return {
        'total_abstained': len(events),
        'abstention_rate': (round(len(events) / total_triage, 4)
                            if total_triage else None),
        'by_cwe': by('cwe'), 'by_rule': by('rule_id'),
        'by_repo': dict(Counter(str(repo_name(e)) for e in events)),
        'by_reason': by('reason'), 'by_tier': by('tier'),
        'evidence_bytes_min': min(evidence) if evidence else None,
        'evidence_bytes_max': max(evidence) if evidence else None,
        'critical_cwe_abstained': len(critical),
        'critical_cwe_breakdown': dict(Counter(e.get('cwe') for e in critical)),
        'top_rules': Counter(str(e.get('rule_id') or '') for e in events).most_common(5),
        'top_repos': Counter(str(repo_name(e)) for e in events).most_common(5),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--store', type=Path,
                    default=ROOT / '.localguard/state.sqlite3')
    ap.add_argument('--total-triage', type=int, default=None)
    args = ap.parse_args()
    events = load(args.store) if args.store.exists() else []
    report = {'kind': 'triage_abstention_report', 'store': str(args.store),
              'warning': 'READ-ONLY. No model started, no DB writes.',
              'summary': summarize(events, args.total_triage)}
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
