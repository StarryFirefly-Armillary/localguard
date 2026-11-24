"""Gold→production contexts must carry NO metadata shortcut to the model.

Regressions locked here:
1. Old-rule negatives must have EMPTY cwe/category (production from_finding()
   default), never 'unknown' — a sentinel would itself separate +/- samples.
2. metadata_origin is audit-only, NEVER in the model context.
3. Counterfactual masks are symmetric across ALL samples.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import evaluate_gold_v0 as ev


def build_records(records, mask=None):
    # Source evidence is irrelevant to metadata mapping; stub BOTH local-file
    # readers so these tests pass in CI, where .localguard/ and .workbuddy/
    # are absent. Production path is covered elsewhere.
    original_lines, original_index = ev.source_lines, ev.tool_call_index
    ev.source_lines = lambda record, tool_calls: [{'line': 1, 'text': 'x = 1'}]
    ev.tool_call_index = lambda: {}
    try:
        return ev.build_records(records, mask=mask)
    finally:
        ev.source_lines, ev.tool_call_index = original_lines, original_index


def _gold_eval():
    p = ROOT / '.workbuddy' / 'gold' / 'gold_v0_eval.jsonl'
    if not p.exists():
        import pytest
        pytest.skip('gold_v0_eval.jsonl not present (gitignored local data)')
    return [json.loads(l) for l in p.read_text(encoding='utf-8').splitlines() if l.strip()]


def _minimal_record(source, cwe, category, title, severity):
    return {'id': 'X', 'source': source, 'human_label': 'likely_true',
            'finding': {'cwe': cwe, 'category': category, 'title': title,
                        'severity': severity, 'locations': [{'path': 'a.py'}],
                        'evidence': [], 'rule_id': None,
                        'file_sha256': 'x', 'path': 'a.py', 'line': 1,
                        'code_lines': 'x = 1'}}


def test_missing_metadata_is_empty_not_unknown():
    r = _minimal_record('old_rule_fp_v2', None, None, 'Weak crypto', 'WARNING')
    ctx, labels, origins = build_records([r])
    c = ctx[0]
    assert c['cwe'] == '' and c['category'] == ''
    assert origins['X']['cwe'] == 'missing'
    for v in c.values():  # no sentinel anywhere in the model payload
        assert v != 'unknown', f'unknown sentinel leaked: {v}'


def test_metadata_origin_not_in_model_context():
    r = _minimal_record('vulnshop_current_scan', 'CWE-89', 'other', 'SQLi', 'high')
    ctx, _, origins = build_records([r])
    assert 'metadata_origin' not in ctx[0]
    assert origins['X']['cwe'] == 'scanner_normalized'
    assert ctx[0]['cwe'] == 'CWE-89'


def test_counterfactual_masks_are_symmetric():
    pos = _minimal_record('vulnshop_current_scan', 'CWE-89', 'other', 'SQLi title', 'high')
    neg = _minimal_record('old_rule_fp_v2', None, None, 'Weak crypto title', 'WARNING')
    neg['id'] = 'Y'
    for mask, expect_title, expect_cwe in (
        (None, True, True), ('title', False, True),
        ('metadata', True, False), ('both', False, False),
    ):
        ctx, _, _ = build_records([pos, neg], mask=mask)
        for c in ctx:
            assert (c['title'] != '') is expect_title, f'mask={mask} id={c["id"]} title={c["title"]!r}'
            if not expect_cwe:
                assert c['cwe'] == '' and c['category'] == ''
            elif c['id'] == 'X':
                assert c['cwe'] == 'CWE-89'
            assert c['severity'] in ('high', 'medium')  # always retained


def test_gold_eval_has_no_unknown_metadata():
    rows = _gold_eval()
    ctx, _, _ = build_records(rows)
    for c in ctx:
        assert c['cwe'] != 'unknown' and c['category'] != 'unknown'
        assert 'metadata_origin' not in c
