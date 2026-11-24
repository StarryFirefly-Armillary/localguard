"""Detection probe must isolate confounds and never train on synthetic rows."""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evaluate_detection_probe import sample_text, is_hint_comment, PROBE
from localguard.training import validate_record


def test_probe_samples_are_explicitly_synthetic():
    rows = [json.loads(l) for l in PROBE.read_text(encoding='utf-8').splitlines() if l.strip()]
    assert len(rows) == 11
    assert all(r.get('role') == 'detection_probe' and r.get('synthetic') is True for r in rows)
    # Current validate_record() refuses to promote synthetic rows to training.
    # NOTE: this is a property of today's validator, not an immutable guarantee —
    # removing the marker or changing the validator would bypass it.
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


def test_strip_hints_removes_fixture_and_safety_comments():
    assert is_hint_comment('# STATIC FIXTURE ONLY. Never import or execute.')
    assert is_hint_comment('// html/template auto-escapes interpolated values')
    assert not is_hint_comment('from html import escape')
    r = json.loads(PROBE.read_text(encoding='utf-8').splitlines()[0])
    full = sample_text(r)
    stripped = sample_text(r, strip_hints=True)
    assert 'STATIC FIXTURE ONLY' not in stripped
    assert 'HTML-escaped' not in stripped
    # real code lines survive
    assert 'escape(comment' in stripped
    assert len(stripped) < len(full)
