"""Baseline evaluation of the current local model on gold_v1 sft_eval.jsonl.

Uses the EXACT messages stored in each sample (system + user) so a post-training
comparison on the same prompts is reproducible. Inference goes through the
production model layer -> live llama-server; no weights/config are modified.

Outputs a JSON artifact with accuracy / precision / recall / FPR / uncertain /
JSON success / timing / VRAM. Never prints bare console numbers as the result.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from localguard.config import Config
from localguard.registry import ToolRegistry

VERDICTS = {'likely_true', 'likely_false', 'uncertain'}


def _vram_mib() -> int | None:
    try:
        out = subprocess.check_output(
            ['nvidia-smi', '--query-gpu=memory.used', '--format=csv,noheader,nounits'],
            text=True, timeout=10)
        return int(out.strip().splitlines()[0])
    except Exception:
        return None


def _metrics(rows: list[dict]) -> dict:
    tp = fp = tn = fn = unc = parse_fail = 0
    for r in rows:
        v = r.get('pred_verdict')
        if v is None:
            parse_fail += 1
            continue
        if v not in VERDICTS:
            parse_fail += 1
            continue
        if v == 'uncertain':
            unc += 1
            continue
        pos = r.get('expected') == 'likely_true'
        if v == 'likely_true':
            tp += pos
            fp += not pos
        else:
            fn += pos
            tn += not pos
    pos_total = tp + fn
    neg_total = fp + tn
    return {
        'samples': len(rows),
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'uncertain': unc, 'parse_failures': parse_fail,
        'accuracy': round((tp + tn) / len(rows), 4) if rows else None,
        'precision': round(tp / (tp + fp), 4) if tp + fp else None,
        'recall': round(tp / pos_total, 4) if pos_total else None,
        'fpr': round(fp / neg_total, 4) if neg_total else None,
        'uncertain_rate': round(unc / len(rows), 4) if rows else None,
        'json_success_rate': round(sum(1 for r in rows if r.get('pred_verdict') is not None) / len(rows), 4) if rows else None,
    }


async def run(eval_path: Path, out: Path, limit: int | None) -> dict:
    rows, skipped = [], []
    for line in eval_path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        answer = json.loads(r['messages'][-1]['content'])
        expected = answer.get('verdict')
        # sft_eval mixes two tasks: triage_finding (verdict) and
        # cve_function_pair (fixed_code). Only triage is a classification
        # task; a pair's assistant JSON has no verdict and must be excluded,
        # otherwise it is a false parse failure, not a model error.
        if expected not in VERDICTS:
            skipped.append({'id': r.get('id'), 'reason': 'not_a_triage_verdict'})
            continue
        rows.append({'id': r['id'], 'messages': r['messages'][:-1], 'expected': expected})
    if limit:
        rows = rows[:limit]
    cfg = Config.load(str(ROOT / 'localguard.local.json'))
    registry = ToolRegistry(cfg)
    vram_before = _vram_mib()
    started = time.time()
    try:
        model = registry.get_model()
        for r in rows:
            try:
                resp = await model._infer(r['messages'], [], '8gb', structured=True, release=False,
                                          max_tokens=256)
                content = resp['choices'][0]['message']['content']
                data = json.loads(content)
                v = data.get('verdict')
                r['pred_verdict'] = v if v in VERDICTS else None
                r['raw_snippet'] = str(content)[:200]
            except Exception as exc:
                r['pred_verdict'] = None
                r['error'] = f'{type(exc).__name__}: {str(exc)[:120]}'
    finally:
        await registry.close()
    elapsed = round(time.time() - started, 2)
    result = {
        'kind': 'gold_v1_sft_baseline',
        'warning': 'BASELINE ONLY — 26 samples; model unmodified. Post-training comparison must use the same prompts.',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'eval_file': str(eval_path),
        'eval_sha256': hashlib.sha256(eval_path.read_bytes()).hexdigest(),
        'model_path': cfg.model_path,
        'model_endpoint': cfg.model_endpoint,
        'code_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'vram_before_mib': vram_before,
        'vram_after_mib': _vram_mib(),
        'elapsed_seconds': elapsed,
        'metrics': _metrics(rows),
        'excluded_non_triage': skipped,
        'per_sample': [{k: v for k, v in r.items() if k != 'messages'} for r in rows],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'artifact': str(out), 'metrics': result['metrics'],
                      'elapsed_seconds': elapsed}, ensure_ascii=False, indent=2))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--eval', type=Path, default=ROOT / '.workbuddy/training_data/gold_v1/sft_eval.jsonl')
    p.add_argument('--out', type=Path, default=ROOT / '.workbuddy/training_data/gold_v1/baseline_current_model.json')
    p.add_argument('--limit', type=int, default=None)
    a = p.parse_args()
    asyncio.run(run(a.eval, a.out, a.limit))


if __name__ == '__main__':
    main()
