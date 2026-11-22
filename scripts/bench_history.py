"""Append a benchmark result to a local recall history and print the trend.

Usage:
    python scripts/bench_history.py --append benchmarks/last-run.json
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HISTORY = ROOT / 'benchmarks' / 'history.jsonl'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--append', type=Path, help='Benchmark result JSON to record')
    parser.add_argument('--show', action='store_true', help='Print the recorded trend')
    args = parser.parse_args()

    if args.append:
        data = json.loads(Path(args.append).read_text(encoding='utf-8'))
        record = {
            'at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'recall': data.get('recall'),
            'detected': data.get('detected'),
            'total': data.get('total_vulnerabilities'),
            'issues': data.get('issues'),
        }
        with HISTORY.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + '\n')
        print('recorded:', record)

    if HISTORY.is_file():
        rows = [json.loads(line) for line in HISTORY.read_text(encoding='utf-8').splitlines() if line.strip()]
        if rows:
            print('\nrecall trend:')
            for row in rows[-10:]:
                print(f"  {row['at'][:10]}  {row['recall']:>5}%  {row['detected']}/{row['total']}  ({row['issues']} issues)")
            if len(rows) >= 2 and rows[-1]['recall'] < rows[-2]['recall']:
                print('  WARNING: recall decreased vs previous run')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
