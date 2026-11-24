"""SFT sampling must count supervised LABELS, never legacy clean_evidence source."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from train_sft_gold import load_sft, sample_balanced


def _row(i, label, kind='triage_finding', source='tool_call'):
    return {'id': f'X{i}', 'sample_kind': kind, 'human_label': label,
            'label': label, 'source': source,
            'messages': [{'role': 'system', 'content': 's'},
                         {'role': 'user', 'content': 'u'},
                         {'role': 'assistant', 'content': 'a'}]}


def test_ratio_counts_labels_not_source():
    # All rows share source='tool_call' (legacy code would call them all positive).
    rows = [_row(i, 'likely_true') for i in range(10)]
    rows += [_row(100 + i, 'likely_false') for i in range(10)]
    chosen, m = sample_balanced(rows, max_negative_ratio=0.5)
    assert m['positive_turns'] == 10 and m['negative_turns'] == 10
    assert m['chosen_positive'] == 10 and m['chosen_negative'] == 5
    ids = [r['id'] for r in chosen]
    assert len([i for i in ids if i.startswith('X1') and int(i[1:]) >= 100]) == 5


def test_sampling_is_order_independent_and_seeded():
    rows = [_row(i, 'likely_true') for i in range(6)]
    rows += [_row(100 + i, 'likely_false') for i in range(6)]
    a, ma = sample_balanced(rows, 1.0)
    b, mb = sample_balanced(list(reversed(rows)), 1.0)
    assert [r['id'] for r in a] == [r['id'] for r in b]
    assert ma['chosen_total'] == mb['chosen_total'] == 12


def test_pairs_are_preserved_excluded_from_ratio():
    rows = [_row(1, 'likely_true'), _row(2, 'likely_false')]
    rows += [_row(3, 'vulnerable_fixed_pair', kind='cve_function_pair')]
    chosen, m = sample_balanced(rows, 0.0)
    assert m['pair_turns'] == 1
    assert any(r['id'] == 'X3' for r in chosen)
    assert m['chosen_negative'] == 0
