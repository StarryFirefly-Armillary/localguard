"""Production triage evaluator must separate coverage from quality."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evaluate_production_triage import _metrics, OUTPUT_FIELDS, PLACEHOLDER_EXPLANATION, PLACEHOLDER_REMEDIATION


def _row(label, verdict, **fields):
    base = dict(expected=label, verdict=verdict, explanation='e', remediation='r',
                confidence=0.7, reason='why')
    base.update(fields)
    return base


def test_conditional_and_whole_sample_metrics_both_reported():
    rows = ([_row('likely_true', 'likely_true'), _row('likely_true', 'likely_true')] +
            [_row('likely_false', 'likely_true'), _row('likely_false', 'likely_true'),
             _row('likely_false', 'likely_true')] +
            [_row('likely_false', 'likely_false'),
             _row('likely_true', None), _row('likely_false', None)])
    m = _metrics(rows)
    # conditional metrics over 7 verdict-present samples
    assert m['triaged_samples'] == 6 and m['missing_verdict'] == 2
    assert m['conditional_precision'] == round(2 / 5, 4)  # 2 tp / (2 tp + 3 fp)
    assert m['conditional_fpr'] == 0.75  # 3 fp / 4 judged negatives
    # whole-sample negative view includes abstentions
    assert m['all_negative_false_positive'] == 0.6  # 3 fp / 5 negatives
    assert m['all_negative_abstention'] == 0.2  # 1 abstention / 5 negatives
    assert 'conditional_fpr' in m and 'all_negative_false_positive' in m


def test_positive_and_negative_coverage_separated():
    rows = [_row('likely_true', 'likely_true'), _row('likely_true', None),
            _row('likely_false', None), _row('likely_false', None)]
    m = _metrics(rows)
    assert m['positive_coverage'] == 0.5
    assert m['negative_coverage'] == 0.0
    assert m['negative_abstention'] == 1.0
    assert m['verdict_completeness'] == 0.25  # 1 of 4 has a verdict


def test_uncertain_denominator_is_triaged_subset():
    rows = [_row('likely_true', 'uncertain'), _row('likely_false', 'uncertain'),
            _row('likely_true', None)]
    m = _metrics(rows)
    assert m['uncertain'] == 2 and m['uncertain_rate'] == 1.0  # 2/2, not 2/3
    assert m['conditional_precision'] is None  # no binary verdicts


def test_five_field_completeness_uses_fixed_tuple():
    # Regression: the old code iterated field_stats (which contains
    # 'all_fields'), so all() always failed and all_fields stayed 0.
    full = _row('likely_true', 'likely_true')
    partial = _row('likely_true', 'likely_true', reason='')
    assert all(full.get(k) not in (None, '') for k in OUTPUT_FIELDS)
    assert not all(partial.get(k) not in (None, '') for k in OUTPUT_FIELDS)
    assert 'all_fields' not in OUTPUT_FIELDS  # the bug: iterating field_stats


def test_placeholder_identifiable_by_fixed_text():
    item = {'explanation': PLACEHOLDER_EXPLANATION, 'remediation': PLACEHOLDER_REMEDIATION}
    assert item['explanation'] == '模型未提供说明，请依据下方证据人工判断。'
    assert item['remediation'] == '暂无模型修复建议，请依据原始证据人工判断。'
