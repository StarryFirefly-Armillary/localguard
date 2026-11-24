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


def test_no_hint_removes_EVERY_comment_line():
    # Strict control: any comment line is stripped, not just a keyword subset.
    # These previously leaked (8/11 samples) under the old keyword regex.
    assert is_hint_comment('# STATIC FIXTURE ONLY. Never import or execute.')
    assert is_hint_comment('// html/template auto-escapes interpolated values')
    assert is_hint_comment('    # Constant-time comparison of a SHA-256 digest.')
    assert is_hint_comment('    // Bound parameter prevents SQL injection.')
    assert is_hint_comment('    # Secret is read from the process environment.')
    # real code (including inline "#" inside a value) must survive
    assert not is_hint_comment('from html import escape')
    assert not is_hint_comment('    actual = hashlib.sha256(data).hexdigest()')
    rows = [json.loads(l) for l in PROBE.read_text(encoding='utf-8').splitlines() if l.strip()]
    for r in rows:
        stripped = sample_text(r, strip_hints=True)
        for ln in r['result']['lines']:
            if is_hint_comment(ln['text']):
                assert ln['text'].strip() not in stripped, f"comment leaked: {r['id']}"
        # every real code line survives
        for ln in r['result']['lines']:
            if not is_hint_comment(ln['text']) and ln['text'].strip():
                assert ln['text'].strip() in stripped, f"code lost: {r['id']}"
