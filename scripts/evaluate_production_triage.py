"""Production-path triage evaluator on gold_v1 findings.

Uses the REAL production explain_issues(triage=True) path: full system prompt,
5-field schema (explanation/remediation/verdict/confidence/reason), batching,
max_tokens, parsing, degradation and self-heal — NOT a simplified verdict-only
prompt. This closes the gap found in the first SFT experiment.

Input: gold_v1 triage_finding records -> production explain_issues context shape.
Output: JSON artifact with triage precision/recall/FPR, uncertain rate, JSON
success rate, per-field completeness, critical-miss list, timing.

No deployment action. Requires a running llama-server at the configured endpoint.
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
sys.path.insert(0, str(ROOT / 'scripts'))

from localguard.config import Config
from localguard.registry import ToolRegistry

VERDICTS = {'likely_true', 'likely_false', 'uncertain'}
# Critical CWEs that must not be missed (safety regressions).
CRITICAL_CWE = {'CWE-78', 'CWE-89', 'CWE-611', 'CWE-918', 'CWE-502', 'CWE-22'}


def gold_to_context(record: dict) -> dict:
    """Map a gold_v1 triage record into production explain_issues input shape."""
    f = record['finding']
    loc = (f.get('locations') or [{}])[0]
    source = f.get('source') or []
    if isinstance(source, str):
        source = [{'line': loc.get('line', 1), 'text': source}]
    return {
        'id': record['id'],
        'title': f.get('title') or '',
        'severity': f.get('severity') or 'medium',
        'category': f.get('category') or 'other',
        'cwe': f.get('cwe') or '',
        'confidence': f.get('confidence', 0.7),
        'locations': f.get('locations') or [loc],
        'evidence': f.get('evidence') or [],
        'source': source,
        'source_truncated': f.get('source_truncated', False),
    }


def _metrics(results: list[dict]) -> dict:
    """Separate COVERAGE (verdict provided) from triage QUALITY.

    Production explain_issues() self-heals findings the model did not triage
    into placeholder entries with no verdict. Counting those as 'false' would
    confound coverage with classification quality.
    """
    tp = fp = tn = fn = unc = missing = 0
    for r in results:
        v = r.get('verdict')
        if v is None:
            missing += 1
            continue
        if v == 'uncertain':
            unc += 1
            continue
        pos = r['expected'] == 'likely_true'
        if v == 'likely_true':
            tp += pos; fp += not pos
        else:
            fn += pos; tn += not pos
    n = len(results)
    triaged = n - missing  # verdict present (incl. uncertain)
    return {
        'samples': n,
        'verdict_coverage': round(triaged / n, 4) if n else None,
        'missing_verdict': missing,
        'triaged_samples': triaged,
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'uncertain': unc,
        # quality metrics are over the TRIAGED subset, not all samples
        'accuracy': round((tp + tn) / triaged, 4) if triaged else None,
        'precision': round(tp / (tp + fp), 4) if tp + fp else None,
        'recall': round(tp / (tp + fn), 4) if tp + fn else None,
        'fpr': round(fp / (fp + tn), 4) if fp + tn else None,
        'uncertain_rate': round(unc / triaged, 4) if triaged else None,
        'json_success_rate': round(triaged / n, 4) if n else None,
    }


async def run(eval_path: Path, out: Path, limit: int | None) -> dict:
    rows = []
    for line in eval_path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get('sample_kind') != 'triage_finding':
            continue
        rows.append({'expected': r.get('human_label') or r.get('label'),
                     'cwe': (r.get('finding') or {}).get('cwe'),
                     'context': gold_to_context(r)})
    if limit:
        rows = rows[:limit]
    cfg = Config.load(str(ROOT / 'localguard.local.json'))
    registry = ToolRegistry(cfg)
    # Hook the production logger to capture FIRST-TRY JSON errors and
    # self-heal events — the production path logs these but does not surface
    # them in its return value.
    log_events = []
    started = time.time()
    try:
        model = registry.get_model()
        original_log = model._log

        def capture_log(event, **values):
            if event in ('model_explanation_json_error', 'model_explanation_error_trace'):
                log_events.append({'event': event,
                                   'position': values.get('position'),
                                   'excerpt': str(values.get('excerpt', ''))[:200]})
            return original_log(event, **values)

        model._log = capture_log
        verdicts = await model.explain_issues([r['context'] for r in rows], '8gb', triage=True)
    finally:
        await registry.close()
    elapsed = round(time.time() - started, 2)
    json_errors = [e for e in log_events if e['event'] == 'model_explanation_json_error']

    results, field_stats = [], {'explanation': 0, 'remediation': 0, 'verdict': 0,
                                'confidence': 0, 'reason': 0, 'all_fields': 0}
    for r in rows:
        item = verdicts.get(r['context']['id']) or {}
        for key in ('explanation', 'remediation', 'verdict', 'confidence', 'reason'):
            if item.get(key) not in (None, ''):
                field_stats[key] += 1
        if all(item.get(k) not in (None, '') for k in field_stats):
            field_stats['all_fields'] += 1
        results.append({'id': r['context']['id'], 'expected': r['expected'], 'cwe': r['cwe'],
                        'verdict': item.get('verdict'), 'confidence': item.get('confidence'),
                        'explanation_chars': len(str(item.get('explanation', ''))),
                        'remediation_chars': len(str(item.get('remediation', ''))),
                        'reason_chars': len(str(item.get('reason', '')))})
    critical_miss = [r['id'] for r in results
                     if r['expected'] == 'likely_true'
                     and r['cwe'] in CRITICAL_CWE
                     and r['verdict'] != 'likely_true']
    gguf = Path(cfg.model_path)
    report = {
        'kind': 'gold_v1_production_triage_eval',
        'warning': 'EXPLORATORY — production explain_issues() path, frozen eval split only.',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'eval_sha256': hashlib.sha256(eval_path.read_bytes()).hexdigest(),
        'model_endpoint': cfg.model_endpoint, 'model_path': cfg.model_path,
        'model_sha256': hashlib.sha256(gguf.read_bytes()).hexdigest() if gguf.is_file() else None,
        'server_start_command': (
            'llama-server.exe --model <cfg.model_path> --ctx-size 4096 --n-gpu-layers 99 '
            '--host 127.0.0.1 --port 17865 --alias qwen3.5-4b'),
        'failed_adapter_loaded': False,  # config does not reference adapter-gold-v1-1ep
        'code_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'path': 'explain_issues(triage=True) — full schema, batching, parsing, degradation',
        'batches': (len(rows) + 3) // 4,
        'elapsed_seconds': elapsed,
        'first_try_json_success_rate': round((((len(rows) + 3) // 4) - len(json_errors)) / max(1, (len(rows) + 3) // 4), 4),
        'json_error_events': json_errors,
        'metrics': _metrics(results),  # json_success_rate here = post-self-heal verdict completeness
        'field_completeness': field_stats,
        'critical_cwe_missed': critical_miss,
        'error_details': [r for r in results if r['verdict'] is None],
        'per_sample': results,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'artifact': str(out), 'metrics': report['metrics'],
                      'field_completeness': field_stats,
                      'critical_missed': len(critical_miss)}, ensure_ascii=False, indent=2))
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--eval', type=Path, default=ROOT / '.workbuddy/training_data/gold_v1/eval.jsonl')
    p.add_argument('--out', type=Path, default=ROOT / 'benchmarks/model_eval/gold_v1_1ep/production_triage_eval.json')
    p.add_argument('--limit', type=int, default=None)
    a = p.parse_args()
    asyncio.run(run(a.eval, a.out, a.limit))


if __name__ == '__main__':
    main()
