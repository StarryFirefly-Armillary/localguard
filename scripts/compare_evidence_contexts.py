"""Budget-safe evidence-completeness comparison on gold_v0_eval (18 samples).

Only ONE variable changes between the two conditions — context size — since
comments/docstrings are stripped in BOTH:
  window_code_only         : original +/-3-line window, comments stripped
  full_code_only_budgeted  : enclosing function at FULL_BUDGET_CAP=500 chars,
                             comments stripped; cap chosen statically so every
                             batch stays <=7500 bytes (production budget 8000).

Both conditions must reach 18/18 verdict coverage. Any missing verdict marks
the condition invalid and no significance claim is made.

Reuses the production explain_issues() path (schema/batching/tokens/parsing
all shared). No prompt change, no retrain, no pool expansion, no cap sweep.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from evaluate_gold_v0 import build_records, load_jsonl, metrics, git_output
from localguard.config import Config
from localguard.registry import ToolRegistry

GOLD = ROOT / '.workbuddy' / 'gold'
CONDITIONS = [
    ('window_code_only', 'window_code_only', 'main'),
    ('full_code_only_budgeted', 'full_code_only_budgeted', 'main'),
]


async def run(input_path: Path, out: Path) -> dict:
    gold = load_jsonl(input_path)
    config = Config.load(str(ROOT / 'localguard.local.json'))
    registry = ToolRegistry(config)
    results = {}
    try:
        model = registry.get_model()
        for name, evidence, role in CONDITIONS:
            contexts, labels, origins = build_records(gold, evidence=evidence)
            # A condition can fail for a REAL production reason (e.g. the
            # 8000-byte evidence budget). Record that as invalid rather than
            # aborting the whole comparison — the other conditions still run.
            try:
                verdicts = await model.explain_issues(contexts, '8gb', triage=True)
            except Exception as exc:
                results[name] = {
                    'role': role, 'evidence': evidence, 'valid': False,
                    'error': f'{type(exc).__name__}: {str(exc)[:200]}',
                    'coverage': 0, 'total': len(contexts),
                    'reason': 'condition could not run through production path',
                }
                print(f'{name:18} INVALID — {type(exc).__name__}: {str(exc)[:120]}')
                continue
            m = metrics(contexts, verdicts, labels)
            covered = m['triaged_count']
            results[name] = {
                'role': role,
                'evidence': evidence,
                'coverage': covered,
                'total': len(contexts),
                'valid': covered == len(contexts),
                'metrics': m,
                'evidence_basis': {k: v.get('evidence_basis') for k, v in origins.items()},
                'per_sample': {
                    c['id']: {
                        'label': labels[c['id']],
                        'verdict': (verdicts.get(c['id']) or {}).get('verdict'),
                        'confidence': (verdicts.get(c['id']) or {}).get('confidence'),
                    }
                    for c in contexts
                },
            }
            b = m['binary']
            print(f'{name:18} coverage={covered}/{len(contexts)} valid={results[name]["valid"]} '
                  f'TP={b["tp"]} FP={b["fp"]} TN={b["tn"]} FN={b["fn"]} '
                  f'FPR={b["false_positive_rate"]} recall={b["recall"]}')
    finally:
        await registry.close()
    main_valid = all(results.get(n, {}).get('valid') for n, _, r in CONDITIONS if r == 'main')
    report = {
        'kind': 'gold_v0_evidence_comparison',
        'warning': 'EXPLORATORY — 18 samples, single run. Not a model-quality conclusion.',
        'input': str(input_path),
        'input_sha256': hashlib.sha256(input_path.read_bytes()).hexdigest(),
        'code_commit': git_output('rev-parse', 'HEAD'),
        'model_path': config.model_path,
        'main_comparison_valid': main_valid,
        'judgement_rule': (
            'If window_code_only already cuts FPR substantially -> comment leakage was primary. '
            'If only full_code_only cuts FPR -> truncated safety context was primary. '
            'If neither cuts FPR -> turn to model prior / confidence calibration. '
            'Only adopt full function in engine.py if it stably lowers FPR without hurting recall.'),
        'conditions': results,
    }
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'written {out}; main_comparison_valid={main_valid}')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, default=GOLD / 'gold_v0_eval.jsonl')
    p.add_argument('--out', type=Path, default=GOLD / 'gold_v0_evidence_comparison.json')
    a = p.parse_args()
    asyncio.run(run(a.input, a.out))


if __name__ == '__main__':
    main()
