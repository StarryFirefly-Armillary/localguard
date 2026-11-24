"""Paired gold evaluation metrics must use two conditions, not model-vs-label McNemar."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from evaluate_gold_v0 import metrics, paired_mcnemar


def _rows():
    return [{'id': 'A'}, {'id': 'B'}, {'id': 'C'}, {'id': 'D'}]


def test_binary_metrics_and_uncertain_are_separate():
    rows = _rows()
    labels = {'A': 'likely_true', 'B': 'likely_true', 'C': 'likely_false', 'D': 'likely_false'}
    verdicts = {
        'A': {'verdict': 'likely_true'},
        'B': {'verdict': 'uncertain'},
        'C': {'verdict': 'likely_true'},
        'D': {'verdict': 'likely_false'},
    }
    result = metrics(rows, verdicts, labels)
    assert result['binary'] == {
        'tp': 1, 'fp': 1, 'tn': 1, 'fn': 1,
        'precision': 0.5, 'recall': 0.5, 'false_positive_rate': 0.5,
        'fpr_wilson95': result['binary']['fpr_wilson95'],
    }
    assert result['uncertain_count'] == 1
    assert result['exact_accuracy'] == 0.5


def test_paired_mcnemar_compares_conditions():
    rows = _rows()
    before = {
        'A': {'verdict': 'likely_true'}, 'B': {'verdict': 'likely_true'},
        'C': {'verdict': 'likely_false'}, 'D': {'verdict': 'likely_false'},
    }
    after = {
        'A': {'verdict': 'likely_false'}, 'B': {'verdict': 'likely_true'},
        'C': {'verdict': 'likely_true'}, 'D': {'verdict': 'likely_false'},
    }
    result = paired_mcnemar(rows, before, after)
    assert result['paired_count'] == 4
    assert result['excluded_missing_verdict'] == 0
    assert result['comparison_valid'] is True
    assert result['baseline_positive_conservative_negative'] == 1
    assert result['baseline_negative_conservative_positive'] == 1
    assert result['exact_p'] == 1.0


def test_paired_mcnemar_excludes_missing_verdicts():
    rows = [{'id': 'A'}, {'id': 'B'}]
    before = {'A': {'verdict': 'likely_true'}, 'B': {'verdict': 'likely_true'}}
    after = {'A': {'verdict': 'likely_false'}, 'B': {}}
    result = paired_mcnemar(rows, before, after)
    assert result['paired_count'] == 1
    assert result['excluded_missing_verdict'] == 1
    assert result['comparison_valid'] is False
    assert result['baseline_positive_conservative_negative'] == 1
