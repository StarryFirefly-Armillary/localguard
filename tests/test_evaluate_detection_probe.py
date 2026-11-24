"""Detection probe must isolate confounds and never train on synthetic rows.

These tests build their OWN minimal samples so they pass in CI, where the
gitignored .workbuddy/pilot_clean data does not exist. A separate integration
test runs against the real data only when it is present locally.
"""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evaluate_detection_probe import sample_text, is_hint_comment, PROBE
from localguard.training import validate_record


def _sample() -> dict:
    """Minimal production-shape probe record, built inline (no external file)."""
    return {
        'id': 'clean-pilot-inline',
        'source': 'clean_evidence',
        'role': 'detection_probe',
        'synthetic': True,
        'result': {'lines': [
            {'line': 1, 'text': '# STATIC FIXTURE ONLY. Never import or execute.'},
            {'line': 2, 'text': 'from html import escape'},
            {'line': 3, 'text': '    # Constant-time comparison of a SHA-256 digest.'},
            {'line': 4, 'text': '    actual = hashlib.sha256(data).hexdigest()'},
        ]},
    }


def test_probe_samples_are_explicitly_synthetic():
    r = _sample()
    assert r['role'] == 'detection_probe' and r['synthetic'] is True
    # Current validate_record() refuses to promote synthetic rows to training.
    # NOTE: property of today's validator, not an immutable guarantee.
    try:
        validate_record(r)
    except Exception as exc:
        assert 'Synthetic' in str(exc)
    else:
        raise AssertionError('synthetic probe record passed training validation!')


def test_sample_text_builds_numbered_evidence():
    text = sample_text(_sample())
    assert text.startswith('File: ')
    assert '1: # STATIC FIXTURE ONLY' in text
    assert '2: from html import escape' in text


def test_no_hint_removes_EVERY_comment_line():
    # Strict control: any comment line is stripped, not just a keyword subset.
    assert is_hint_comment('# STATIC FIXTURE ONLY. Never import or execute.')
    assert is_hint_comment('// html/template auto-escapes interpolated values')
    assert is_hint_comment('    # Constant-time comparison of a SHA-256 digest.')
    assert is_hint_comment('    // Bound parameter prevents SQL injection.')
    assert is_hint_comment('    # Secret is read from the process environment.')
    assert not is_hint_comment('from html import escape')
    assert not is_hint_comment('    actual = hashlib.sha256(data).hexdigest()')
    r = _sample()
    full, stripped = sample_text(r), sample_text(r, strip_hints=True)
    assert 'STATIC FIXTURE ONLY' not in stripped
    assert 'Constant-time comparison' not in stripped
    assert 'from html import escape' in stripped
    assert 'hashlib.sha256(data).hexdigest()' in stripped
    assert len(stripped) < len(full)


def test_real_probe_data_when_present():
    """Integration check against real pilot data; skipped in CI."""
    import pytest
    if not PROBE.exists():
        pytest.skip('local pilot_clean data not present (gitignored)')
    rows = [json.loads(l) for l in PROBE.read_text(encoding='utf-8').splitlines() if l.strip()]
    assert len(rows) == 11
    assert all(r.get('role') == 'detection_probe' and r.get('synthetic') is True for r in rows)
    for r in rows:
        stripped = sample_text(r, strip_hints=True)
        for ln in r['result']['lines']:
            if is_hint_comment(ln['text']):
                assert ln['text'].strip() not in stripped, f"comment leaked: {r['id']}"
            elif ln['text'].strip():
                assert ln['text'].strip() in stripped, f"code lost: {r['id']}"
