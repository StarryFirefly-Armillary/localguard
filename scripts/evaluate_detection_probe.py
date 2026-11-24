"""DETECTION probe on the 11 synthetic clean samples (NOT a triage probe).

These samples are clean_evidence with issues=[] — the scanner found nothing.
Testing them with a detection prompt answers "does the model invent findings
in safe code", NOT "does it mis-triage a validated finding". Per the fuel
recommendations they are labelled role=detection_probe, synthetic=true; the
training validator correctly refuses to promote them to training samples.

Uses the SAME detection SYSTEM prompt as evaluate_holdout.py (imported, not
copied) so the probe is comparable to the existing detection baseline. Runs
through the live llama-server via localguard's model layer (same Q4_K_M model,
temperature 0, thinking off). The transformers-vs-HTTP path difference is
disclosed in the report.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from evaluate_holdout import SYSTEM  # same detection prompt, not a copy
from localguard.config import Config
from localguard.model import _json
from localguard.registry import ToolRegistry

PROBE = ROOT / '.workbuddy' / 'pilot_clean' / 'pilot_clean_evidence.jsonl'


def sample_text(record: dict) -> str:
    lines = record['result'].get('lines', [])
    evidence = '\n'.join(f"{ln['line']}: {ln['text']}" for ln in lines)
    return 'File: ' + record['id'].replace('clean-pilot-', '') + '\n' + evidence


async def run(out: Path | None) -> dict:
    rows = [json.loads(l) for l in PROBE.read_text(encoding='utf-8').splitlines() if l.strip()]
    assert all(r.get('role') == 'detection_probe' and r.get('synthetic') is True for r in rows), \
        'probe records must be explicitly marked synthetic; never train on them'
    cfg = Config.load(str(ROOT / 'localguard.local.json'))
    registry = ToolRegistry(cfg)
    results = []
    try:
        model = registry.get_model()
        for r in rows:
            messages = [
                {'role': 'system', 'content': SYSTEM},
                {'role': 'user', 'content': sample_text(r)},
            ]
            raw = ''
            try:
                # evaluate_holdout relies on the prompt for JSON (no response_format);
                # keep structured=False so decoding matches that baseline.
                response = await model._infer(messages, [], '8gb', structured=False, release=False,
                                              max_tokens=256)
                raw = response['choices'][0]['message']['content']
            except Exception as exc:
                results.append({'id': r['id'], 'error': f'{type(exc).__name__}: {str(exc)[:100]}'})
                continue
            invented = None
            try:
                data = json.loads(raw)
                invented = bool(data.get('issues')) if isinstance(data, dict) and isinstance(data.get('issues'), list) else None
            except (ValueError, TypeError):
                invented = None
            results.append({'id': r['id'], 'model_reported_issue': invented,
                            'raw_valid_json': invented is not None})
    finally:
        await registry.close()
    valid = [r for r in results if r.get('model_reported_issue') is not None]
    false_alarms = [r for r in valid if r['model_reported_issue']]
    report = {
        'kind': 'detection_probe_on_synthetic_clean_samples',
        'warning': 'DETECTION task, not triage. Samples have NO scanner finding to triage; this measures invention of findings in safe code only.',
        'path_disclosure': 'same detection SYSTEM prompt as evaluate_holdout.py; inference via live llama-server HTTP (Q4_K_M, temp=0, thinking off) instead of that script transformers path; model weights identical.',
        'samples': len(rows),
        'valid_json': len(valid),
        'false_alarms': len(false_alarms),
        'false_alarm_rate': round(len(false_alarms) / len(valid), 4) if valid else None,
        'per_sample': results,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if out:
        out.write_text(text, encoding='utf-8')
    print(text)
    return report


def main():
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path)
    a = p.parse_args()
    asyncio.run(run(a.out))


if __name__ == '__main__':
    main()
