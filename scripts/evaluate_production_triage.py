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
# The five fields the production explain_issues schema asks for.
OUTPUT_FIELDS = ('explanation', 'remediation', 'verdict', 'confidence', 'reason')
# Production self-heal placeholder texts (fixed strings, not model output).
PLACEHOLDER_EXPLANATION = '模型未提供说明，请依据下方证据人工判断。'
PLACEHOLDER_REMEDIATION = '暂无模型修复建议，请依据原始证据人工判断。'


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


def _is_placeholder(item: dict) -> bool:
    """Identify a production self-heal placeholder by its FIXED text.

    NOTE: this identifies the placeholder, NOT its generation cause. The
    production path inserts the same text for missing/null/id-mismatched
    entries and may drop triage fields from an otherwise real explanation.
    Without the raw batch response the two cannot be distinguished here.
    """
    return (item.get('explanation') == PLACEHOLDER_EXPLANATION
            and item.get('remediation') == PLACEHOLDER_REMEDIATION)


def _field_completeness(items: list[dict]) -> dict:
    """Count the five output fields over items. Iterates the FIXED tuple.

    Regression: the old inline code iterated `field_stats` (which contains the
    not-yet-computed 'all_fields' key), so all() always failed and all_fields
    stayed 0. This is the single source of truth used by run() AND its tests.
    """
    stats = {k: 0 for k in OUTPUT_FIELDS}
    stats['all_fields'] = 0
    for item in items:
        present = [item.get(k) not in (None, '') for k in OUTPUT_FIELDS]
        for key, ok in zip(OUTPUT_FIELDS, present):
            if ok:
                stats[key] += 1
        if all(present):
            stats['all_fields'] += 1
    return stats


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
    pos = [r for r in results if r['expected'] == 'likely_true']
    neg = [r for r in results if r['expected'] == 'likely_false']
    pos_cov = sum(1 for r in pos if r['verdict'] is not None)
    neg_cov = sum(1 for r in neg if r['verdict'] is not None)
    return {
        'samples': n, 'positive_samples': len(pos), 'negative_samples': len(neg),
        'verdict_completeness': round(triaged / n, 4) if n else None,
        'positive_coverage': round(pos_cov / len(pos), 4) if pos else None,
        'negative_coverage': round(neg_cov / len(neg), 4) if neg else None,
        'negative_abstention': round((len(neg) - neg_cov) / len(neg), 4) if neg else None,
        'missing_verdict': missing, 'triaged_samples': triaged,
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'uncertain': unc,
        # CONDITIONAL quality metrics — over the verdict-present subset only.
        # These must NOT be presented as whole-sample FPR/recall.
        'conditional_accuracy': round((tp + tn) / triaged, 4) if triaged else None,
        'conditional_precision': round(tp / (tp + fp), 4) if tp + fp else None,
        'conditional_recall': round(tp / (tp + fn), 4) if tp + fn else None,
        'conditional_fpr': round(fp / (fp + tn), 4) if fp + tn else None,
        'uncertain_rate': round(unc / triaged, 4) if triaged else None,
        # WHOLE-positive-sample safety view: abstentions count as NOT caught.
        # Without this, conditional_recall can read 100% while real positives
        # were skipped — the exact failure mode we must not hide.
        'positive_abstention': round((len(pos) - pos_cov) / len(pos), 4) if pos else None,
        'all_sample_recall': round(tp / len(pos), 4) if pos else None,
        'all_sample_false_negative': len(pos) - tp,
        # WHOLE-sample view: negatives that were falsely called true, plus
        # negatives the model abstained on (no verdict) — both are failures
        # from a conservative triage standpoint.
        'all_negative_false_positive': round(fp / len(neg), 4) if neg else None,
        'all_negative_abstention': round((len(neg) - neg_cov) / len(neg), 4) if neg else None,
    }


def _server_process(endpoint: str) -> dict:
    """Best-effort OBSERVED server info (PID + command line), not a constant."""
    info = {'observed': False, 'pid': None, 'command_line': None, 'note': None}
    try:
        port = int(str(endpoint).rstrip('/').rsplit(':', 1)[-1])
        out = subprocess.check_output(
            ['powershell', '-NoProfile', '-Command',
             f"Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue "
             "| Select-Object -First 1 -ExpandProperty OwningProcess"],
            text=True, timeout=15).strip()
        if out.isdigit():
            info['pid'] = int(out)
            cmd = subprocess.check_output(
                ['powershell', '-NoProfile', '-Command',
                 f"(Get-CimInstance Win32_Process -Filter 'ProcessId = {out}').CommandLine"],
                text=True, timeout=15).strip()
            info['command_line'] = cmd[:500] if cmd else None
            info['observed'] = True
    except Exception as exc:
        info['note'] = f'{type(exc).__name__}: {str(exc)[:100]}'
    return info


def _adapter_in_config(cfg) -> bool:
    """Derive adapter usage from config, not a hardcoded False."""
    blob = json.dumps({k: getattr(cfg, k, None) for k in
                       ('model_path', 'model_4gb_path', 'model_name', 'model_endpoint')},
                      ensure_ascii=False).lower()
    return 'adapter-gold-v1-1ep' in blob


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
    log_events, raw_responses = [], []
    server_process = {'observed': False, 'note': 'not captured (server process may stop with registry)'}
    started = time.time()
    try:
        model = registry.get_model()
        # Capture OBSERVED server process BEFORE registry.close() — after close
        # the model client may release the connection and the process query
        # would observe nothing.
        server_process = _server_process(cfg.model_endpoint)
        original_log, original_infer = model._log, model._infer

        def capture_log(event, **values):
            if event in ('model_explanation_json_error', 'model_explanation_error_trace'):
                log_events.append({'event': event,
                                   'position': values.get('position'),
                                   'excerpt': str(values.get('excerpt', ''))[:200]})
            return original_log(event, **values)

        async def capture_infer(messages, tools, tier, *args, **kwargs):
            resp = await original_infer(messages, tools, tier, *args, **kwargs)
            # Capture the FULL raw response for a local eval artifact (no cap)
            # — a hash or head-only excerpt cannot explain a missing entry that
            # occurred at the tail of the JSON. Full text stays local only.
            try:
                content = resp['choices'][0]['message']['content']
                raw_responses.append({'sha256': hashlib.sha256(content.encode()).hexdigest(),
                                      'chars': len(content),
                                      'content': content})
            except (KeyError, IndexError, TypeError):
                raw_responses.append({'sha256': None, 'chars': 0, 'content': ''})
            return resp

        model._log = capture_log
        model._infer = capture_infer
        verdicts = await model.explain_issues([r['context'] for r in rows], '8gb', triage=True)
    finally:
        await registry.close()
    elapsed = round(time.time() - started, 2)
    json_errors = [e for e in log_events if e['event'] == 'model_explanation_json_error']

    results, placeholder_ids = [], []
    for r in rows:
        item = verdicts.get(r['context']['id']) or {}
        present = {k: item.get(k) not in (None, '') for k in OUTPUT_FIELDS}
        is_placeholder = _is_placeholder(item)
        if is_placeholder:
            placeholder_ids.append(r['context']['id'])
        results.append({'id': r['context']['id'], 'expected': r['expected'], 'cwe': r['cwe'],
                        'verdict': item.get('verdict'), 'confidence': item.get('confidence'),
                        'verdict_present': present['verdict'],
                        'confidence_present': present['confidence'],
                        'reason_present': present['reason'],
                        'is_placeholder': is_placeholder,
                        # store the actual field values (not just char counts)
                        # so the artifact is independently recomputable.
                        'explanation': item.get('explanation'),
                        'remediation': item.get('remediation'),
                        'reason': item.get('reason')})
    critical_miss = [r['id'] for r in results
                     if r['expected'] == 'likely_true'
                     and r['cwe'] in CRITICAL_CWE
                     and r['verdict'] != 'likely_true']
    # Single source of truth for field counting — same function the tests call.
    field_stats = _field_completeness(
        [verdicts.get(r['context']['id']) or {} for r in rows])
    # Actual batch size used by production explain_issues(triage=True).
    batch_size = min(4, cfg.max_prompt_files)
    n_batches = (len(rows) + batch_size - 1) // batch_size
    gguf = Path(cfg.model_path)
    report = {
        'kind': 'gold_v1_production_triage_eval',
        'warning': 'EXPLORATORY — production explain_issues() path, frozen eval split only.',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'eval_sha256': hashlib.sha256(eval_path.read_bytes()).hexdigest(),
        'model_endpoint': cfg.model_endpoint, 'model_path': cfg.model_path,
        'model_sha256': hashlib.sha256(gguf.read_bytes()).hexdigest() if gguf.is_file() else None,
        'config_sha256': hashlib.sha256(
            (ROOT / 'localguard.local.json').read_bytes()).hexdigest(),
        'evaluator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'evaluator_code_commit': subprocess.check_output(
            ['git', 'log', '-1', '--format=%H', '--', str(Path(__file__).relative_to(ROOT))],
            cwd=ROOT, text=True).strip() or None,
        'runtime_head_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        # Observed BEFORE registry.close(); may still be unobservable.
        'server_process': server_process,
        # Renamed: this is config evidence, NOT runtime load proof.
        'failed_adapter_referenced_in_config': _adapter_in_config(cfg),
        'path': 'explain_issues(triage=True) — full schema, batching, parsing, degradation',
        'batch_size': batch_size,
        'batches': n_batches,
        'elapsed_seconds': elapsed,
        # Batch-level JSON SYNTAX parse success (no retry in production).
        'batch_json_parse_success_rate': round(
            (n_batches - len(json_errors)) / max(1, n_batches), 4),
        'batch_json_error_events': json_errors,
        'raw_batch_responses': raw_responses,  # FULL raw content + sha256, local only
        'placeholder_cause_note': (
            f'{len(placeholder_ids)} placeholder entries identified by fixed text. '
            'Generation cause (missing/null/id-mismatch vs invalid-verdict drop) '
            'cannot be distinguished from the final result alone; see '
            'raw_batch_responses for this run\'s full model output.'),
        'placeholder_ids': placeholder_ids,
        'metrics': _metrics(results),
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
