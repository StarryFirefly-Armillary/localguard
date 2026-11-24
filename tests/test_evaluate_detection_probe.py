"""Detection probe must never silently consume synthetic samples as training data."""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evaluate_detection_probe import sample_text, PROBE
from localguard.training import validate_record


def test_probe_samples_are_explicitly_synthetic():
    rows = [json.loads(l) for l in PROBE.read_text(encoding='utf-8').splitlines() if l.strip()]
    assert len(rows) == 11
    assert all(r.get('role') == 'detection_probe' and r.get('synthetic') is True for r in rows)
    # Critical: the validator refuses to promote synthetic rows to training.
    for r in rows:
        try:
            validate_record(r)
        except Exception as exc:
            assert 'Synthetic' in str(exc)
        else:
            raise AssertionError('synthetic probe record passed training validation!')


def test_sample_text_builds_numbered_evidence():
    r = json.loads(PROBE.read_text(encoding='utf-8').splitlines()[0])
    text = sample_text(r)
    assert text.startswith('File: ')
    assert '1: # STATIC FIXTURE ONLY' in text
