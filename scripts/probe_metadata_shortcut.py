"""Counterfactual probes on gold_v0_eval — identify metadata shortcuts.

Runs the SAME production explain_issues() path as the A/B evaluation, with
symmetric masks applied to ALL 18 samples:
  baseline : full context (empty cwe/category for negatives, as in production)
  no_title : title blanked for every sample
  no_meta  : cwe/category blanked for every sample (no-op for negatives already blank)
  both     : title + cwe/category blanked; source + severity only

A probe is VALID only with 18/18 verdict coverage. Missing verdicts mark
comparison_valid=false and no significance claim is made.

This is EXPLORATORY. It does not change prompts, retrain, or expand the pool.
Output is local data under .workbuddy/gold/ (gitignored), not a report.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from evaluate_gold_v0 import build_records, load_jsonl, git_output
from localguard.config import Config
from localguard.registry import ToolRegistry

GOLD = ROOT / '.workbuddy' / 'gold'

CONDITIONS = [
    ('baseline', None),
    ('no_title', 'title'),
    ('no_meta', 'metadata'),
    ('both', 'both'),
]


def binary_counts(verdicts: dict, labels: dict) -> dict:
    tp = fp = tn = fn = unc = 0
    for cid, lab in labels.items():
        v = (verdicts.get(cid) or {}).get('verdict')
        if v not in ('likely_true', 'likely_false'):
            unc += 1
            continue
        pos = lab == 'likely_true'
        if v == 'likely_true':
            tp += pos
            fp += not pos
        else:
            fn += pos
            tn += not pos
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'uncertain': unc,
            'precision': round(tp / (tp + fp), 4) if tp + fp else None,
            'recall': round(tp / (tp + fn), 4) if tp + fn else None,
            'fpr': round(fp / (fp + tn), 4) if fp + tn else None}


async def run(input_path: Path, out: Path) -> dict:
    gold = load_jsonl(input_path)
    config = Config.load(str(ROOT / 'localguard.local.json'))
    registry = ToolRegistry(config)
    results = {}
    try:
        model = registry.get_model()
        for name, mask in CONDITIONS:
            contexts, labels, _ = build_records(gold, mask=mask)
            verdicts = await model.explain_issues(contexts, '8gb', triage=True)
            covered = sum(1 for c in contexts if (verdicts.get(c['id']) or {}).get('verdict') in
                          ('likely_true', 'likely_false', 'uncertain'))
            results[name] = {
                'mask': mask,
                'coverage': covered,
                'total': len(contexts),
                'valid': covered == len(contexts),
                'binary': binary_counts(verdicts, labels),
                'per_sample': {
                    c['id']: {'label': labels[c['id']],
                              'verdict': (verdicts.get(c['id']) or {}).get('verdict'),
                              'confidence': (verdicts.get(c['id']) or {}).get('confidence')}
                    for c in contexts
                },
            }
            print(f'{name}: coverage={covered}/{len(contexts)} valid={results[name]["valid"]} '
                  f'FPR={results[name]["binary"]["fpr"]} recall={results[name]["binary"]["recall"]}')
    finally:
        await registry.close()
    report = {
        'kind': 'gold_v0_metadata_shortcut_probes',
        'warning': 'EXPLORATORY — 18 samples, symmetric masks, single run. Not a model-quality conclusion.',
        'input': str(input_path),
        'input_sha256': hashlib.sha256(input_path.read_bytes()).hexdigest(),
        'code_commit': git_output('rev-parse', 'HEAD'),
        'conditions': results,
        'all_valid': all(r['valid'] for r in results.values()),
    }
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'written {out}; all_valid={report["all_valid"]}')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, default=GOLD / 'gold_v0_eval.jsonl')
    p.add_argument('--out', type=Path, default=GOLD / 'gold_v0_metadata_probes.json')
    a = p.parse_args()
    asyncio.run(run(a.input, a.out))


if __name__ == '__main__':
    main()
