"""DETECTION probe on the 11 synthetic clean samples (NOT a triage probe).

These samples are clean_evidence with issues=[] — the scanner found nothing.
Testing them with a detection prompt answers "does the model invent findings
in safe code", NOT "does it mis-triage a validated finding". Per the fuel
recommendations they are labelled role=detection_probe, synthetic=true; the
training validator correctly refuses to promote them to training samples.

Uses the SAME detection SYSTEM prompt as evaluate_holdout.py (imported, not
copied) so the probe is comparable to the existing detection baseline. Runs
through the live llama-server via localguard's model layer (same Q4_K_M model,
temperature 0, thinking off).

CONFOUND DISCLOSED: the samples carry comment lines that tell the reader the
code is a static fixture and/or explain why it is safe (e.g. "STATIC FIXTURE
ONLY", "Constant-time comparison"). The with-hints baseline therefore cannot
isolate genuine false-alarm behaviour. run() also executes a strict no-hint
variant with ALL comment lines removed. Even so, both are EXPLORATORY probes
on truncated static fixtures: a single-run flip shows sensitivity to prompt
and context, NOT a causal proof, and neither result is a triage-quality claim.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from evaluate_holdout import SYSTEM  # same detection prompt, not a copy
from localguard.config import Config
from localguard.registry import ToolRegistry

PROBE = ROOT / '.workbuddy' / 'pilot_clean' / 'pilot_clean_evidence.jsonl'

# Strict no-hint control: strip ALL comment lines, not a keyword whitelist.
# A prior regex only matched some safety phrases and left 8/11 samples with
# hints like "Constant-time comparison" / "Bound parameter prevents SQL
# injection", so it was a partial control at best. Any line that is a comment
# in the fixture languages (#, //, block-comment continuation) is removed;
# real code lines (imports, defs, calls, string literals) are preserved.
_COMMENT_LINE = re.compile(r'^\s*(?:#|//|/\*|\*)')


def is_hint_comment(text: str) -> bool:
    """True if the line is a comment (stripped in the no-hint control)."""
    return bool(_COMMENT_LINE.match(text))


def sample_text(record: dict, strip_hints: bool = False) -> str:
    lines = record['result'].get('lines', [])
    if strip_hints:
        lines = [ln for ln in lines if not is_hint_comment(ln['text'])]
    evidence = '\n'.join(f"{ln['line']}: {ln['text']}" for ln in lines)
    return 'File: ' + record['id'].replace('clean-pilot-', '') + '\n' + evidence


async def _run_group(model, rows: list[dict], strip_hints: bool) -> dict:
    results = []
    for r in rows:
        messages = [
            {'role': 'system', 'content': SYSTEM},
            {'role': 'user', 'content': sample_text(r, strip_hints=strip_hints)},
        ]
        raw = ''
        try:
            # structured=False so decoding matches evaluate_holdout's baseline.
            # NOTE: _infer() ignores max_tokens when structured=False and pins
            # max_tokens=512 in the payload; the old max_tokens=256 argument had
            # no effect and has been removed. evaluate_holdout uses transformers
            # max_new_tokens=192 — a real token-budget difference (512 vs 192).
            response = await model._infer(messages, [], '8gb', structured=False, release=False)
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
    valid = [r for r in results if r.get('model_reported_issue') is not None]
    false_alarms = [r for r in valid if r['model_reported_issue']]
    return {
        'samples': len(rows),
        'valid_json': len(valid),
        'false_alarms': len(false_alarms),
        'false_alarm_rate': round(len(false_alarms) / len(valid), 4) if valid else None,
        'per_sample': results,
    }


async def run(out: Path | None) -> dict:
    rows = [json.loads(l) for l in PROBE.read_text(encoding='utf-8').splitlines() if l.strip()]
    assert all(r.get('role') == 'detection_probe' and r.get('synthetic') is True for r in rows), \
        'probe records must be explicitly marked synthetic; never train on them'
    cfg = Config.load(str(ROOT / 'localguard.local.json'))
    registry = ToolRegistry(cfg)
    try:
        model = registry.get_model()
        with_hints = await _run_group(model, rows, strip_hints=False)
        no_hint = await _run_group(model, rows, strip_hints=True)
    finally:
        await registry.close()
    report = {
        'kind': 'detection_probe_on_synthetic_clean_samples',
        'warning': 'EXPLORATORY DETECTION probe, not triage and not a controlled experiment. Samples are truncated static fixtures with NO scanner finding. WITH-HINTS is confounded by fixture/safety comments; no_hint removes ALL comment lines. Any between-group flip is single-run, single-sample sensitivity to prompt/context — NOT causal proof. Neither result generalises to real code or measures triage quality.',
        'path_disclosure': 'same detection SYSTEM prompt as evaluate_holdout.py; inference via live llama-server HTTP (Q4_K_M, temp=0, enable_thinking=False) instead of that script transformers path; model weights identical. Token budget DIFFERS: _infer(structured=False) pins max_tokens=512 in the HTTP payload (the previous max_tokens=256 argument was ignored and has been removed); evaluate_holdout uses transformers max_new_tokens=192.',
        'confound': 'sample comment lines include "STATIC FIXTURE ONLY. Never import or execute." and safety explanations ("Constant-time comparison", "Bound parameter prevents SQL injection", etc.); the no_hint group strips ALL comment lines so no safety prose reaches the model.',
        'with_hints': with_hints,
        'no_hint': no_hint,
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
