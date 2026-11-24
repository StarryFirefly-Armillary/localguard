"""window_code_only must differ from window by EXACTLY one variable: comments."""
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evaluate_gold_v0 import build_records, load_jsonl


def test_window_code_only_same_line_range_as_window():
    p = ROOT / '.workbuddy' / 'gold' / 'gold_v0_eval.jsonl'
    if not p.exists():
        import pytest
        pytest.skip('gold eval data not present (gitignored)')
    gold = load_jsonl(p)
    w, _, _ = build_records(gold, evidence='window')
    wc, _, _ = build_records(gold, evidence='window_code_only')
    assert len(w) == len(wc)
    for a, b in zip(w, wc):
        assert [x['line'] for x in a['source']] == [x['line'] for x in b['source']], \
            f'line range changed for {a["id"]}'


def test_window_code_only_strips_labels_not_code():
    p = ROOT / '.workbuddy' / 'gold' / 'gold_v0_eval.jsonl'
    if not p.exists():
        import pytest
        pytest.skip('gold eval data not present (gitignored)')
    gold = load_jsonl(p)
    wc, _, _ = build_records(gold, evidence='window_code_only')
    for c in wc:
        text = '\n'.join(x['text'] for x in c['source'])
        for label in ('VULNERABLE', 'SINK', 'hardcoded'):
            assert label not in text, f'{label} leaked in {c["id"]}'


def test_no_audit_fields_or_unknown_sentinel_in_payload():
    p = ROOT / '.workbuddy' / 'gold' / 'gold_v0_eval.jsonl'
    if not p.exists():
        import pytest
        pytest.skip('gold eval data not present (gitignored)')
    gold = load_jsonl(p)
    for mode in ('window', 'window_code_only', 'full_code_only'):
        ctxs, _, _ = build_records(gold, evidence=mode)
        for c in ctxs:
            assert 'metadata_origin' not in c
            assert 'evidence_basis' not in c
            assert c['cwe'] != 'unknown' and c['category'] != 'unknown'


def test_string_literal_hash_preserved_in_window():
    from evidence_context import strip_window_comments
    lines = [
        {'line': 10, 'text': 'url = "http://x/#frag"  # trailing'},
        {'line': 11, 'text': 'return url'},
    ]
    out = strip_window_comments(lines, 'python')
    assert [x['line'] for x in out] == [10, 11]
    assert 'http://x/#frag' in out[0]['text']
    assert 'trailing' not in out[0]['text']
