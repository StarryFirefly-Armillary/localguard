"""Task-aligned TRIAGE evaluation prototype (smoke test, NOT a quality gate).

Why this exists: the old evaluate_holdout.py measures "can the model find a
vulnerability in raw code" (empty issues = no vuln). Production triage instead
receives ALREADY-VALIDATED scanner findings and emits likely_true/likely_false/
uncertain. Those are different tasks. This prototype uses the production
explain_issues() method directly, so the full inference path is shared:
system prompt, JSON schema, batch_size, max_tokens, parse/degrade logic,
model version/quant and decoding params all come from localguard/model.py.

Scope: ~6 samples from tool_call.jsonl (labelled likely_true candidates).
This validates that the evaluation pipeline computes and reports correctly.
It CANNOT support a claim about model quality. There are no human-confirmed
negatives or uncertain labels, and positives cluster around one CVE family.
Do not use this output to decide a retrain or deployment.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from localguard.config import Config
from localguard.registry import ToolRegistry

CURATION = ROOT / '.localguard' / 'curation'
VERDICTS = {'likely_true', 'likely_false', 'uncertain'}


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% CI for a proportion k/n; (0,0) when n==0."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - margin), min(1.0, centre + margin)


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value for discordant counts (b, c)."""
    n = b + c
    if n == 0:
        return 1.0
    # Binomial two-sided: sum of probabilities <= observed P(X=b).
    k = min(b, c)
    probs = [math.comb(n, i) / (2 ** n) for i in range(n + 1)]
    observed = probs[k]
    return min(1.0, sum(p for p in probs if p <= observed + 1e-15))


def build_records(rows: list[dict]) -> list[dict]:
    """Map tool_call curation records to the exact contexts shape engine uses."""
    out = []
    for row in rows:
        issue = row['issues'][0]
        loc = issue['locations'][0]
        result = row['result']
        lines = result.get('lines', [])
        out.append({
            'id': issue['id'],
            'title': issue['title'][:300],
            'severity': issue['severity'],
            'category': issue['category'],
            'cwe': issue['cwe'],
            'language': result.get('language', 'python'),
            'origin_hint': Path(loc['path']).parent.as_posix()[:200],
            'source': [{'line': ln.get('line'), 'text': ln.get('text', '')[:100]} for ln in lines],
            'source_truncated': bool(result.get('truncated')),
        })
    return out


def summarise(rows: list[dict], verdicts: dict, labels: dict) -> dict:
    """Compute prototype metrics. Labels are expected verdict strings."""
    evaluated = [r for r in rows if r['id'] in verdicts]
    total = len(rows)
    triaged = len(evaluated)
    correct = sum(1 for r in evaluated if (verdicts[r['id']].get('verdict')) == labels.get(r['id']))
    # Standard McNemar discordance: b = label true / predicted false
    # (rejection of a real issue), c = label false / predicted true (false alarm).
    b = c = 0
    for r in evaluated:
        got = verdicts[r['id']].get('verdict')
        want = labels.get(r['id'])
        if got == want:
            continue
        if want == 'likely_true' and got != 'likely_true':
            b += 1
        elif got == 'likely_true' and want != 'likely_true':
            c += 1
    lo, hi = wilson_interval(correct, triaged)
    return {
        'total_samples': total,
        'triaged_count': triaged,
        'coverage': round(triaged / total, 4) if total else 0.0,
        'correct': correct,
        'accuracy_point': round(correct / triaged, 4) if triaged else None,
        'wilson95': [round(lo, 4), round(hi, 4)],
        'mcnemar_b': b, 'mcnemar_c': c,
        'mcnemar_exact_p': round(mcnemar_exact(b, c), 4),
        'verdict_distribution': {
            v: sum(1 for r in evaluated if verdicts[r['id']].get('verdict') == v)
            for v in sorted(VERDICTS)
        },
    }


async def run(limit: int, out: Path | None) -> dict:
    rows = [json.loads(l) for l in (CURATION / 'tool_call.jsonl').read_text(encoding='utf-8').splitlines() if l.strip()]
    rows = rows[:limit]
    records = build_records(rows)
    # These are genuine CVE pre-fix findings → likely_true CANDIDATES.
    # No human-confirmed negatives/uncertain labels exist yet; that limitation
    # is carried into the report rather than hidden.
    labels = {r['id']: 'likely_true' for r in records}

    cfg = Config.load(str(ROOT / 'localguard.local.json'))
    registry = ToolRegistry(cfg)
    report = {
        'kind': 'triage_evaluation_prototype',
        'warning': 'SMOKE TEST ONLY — 6 samples, all likely_true candidates; no human negatives. NOT a model-quality conclusion. Do not use for retrain/deploy decisions.',
        'production_path': 'calls localguard.model.explain_issues(triage=True) directly; system prompt/schema/batch=4/max_tokens=2048/parse-degrade/model-version shared with production',
    }
    try:
        model = registry.get_model()
        verdicts = await model.explain_issues(records, '8gb', triage=True)
        # verdict keys are issue ids (records' id space), not curation row ids.
        report['summary'] = summarise(records, verdicts, labels)
        report['per_sample'] = [
            {'id': r['id'], 'title': r['title'][:60], 'label': labels[r['id']],
             'verdict': verdicts.get(r['id'], {}).get('verdict'),
             'confidence': verdicts.get(r['id'], {}).get('confidence')}
            for r in records
        ]
        report['json_format_success'] = len(verdicts) == len(records)
    finally:
        await registry.close()
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if out:
        out.write_text(text, encoding='utf-8')
    print(text)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--limit', type=int, default=6)
    p.add_argument('--out', type=Path)
    a = p.parse_args()
    asyncio.run(run(a.limit, a.out))


if __name__ == '__main__':
    main()
