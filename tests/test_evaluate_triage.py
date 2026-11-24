"""Statistics and mapping for the triage evaluation prototype."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from evaluate_triage import wilson_interval, mcnemar_exact, summarise

VERDICTS = {'likely_true', 'likely_false', 'uncertain'}


def test_wilson_interval_known_values():
    lo, hi = wilson_interval(2, 7)
    # Small-sample Wilson is wide: ~0.08–0.64 for 2/7.
    assert 0.05 < lo < 0.15 and 0.55 < hi < 0.75
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_mcnemar_exact():
    # b=1,c=0 → two-sided p=1.0 (the recommendation's finding)
    assert mcnemar_exact(1, 0) == 1.0
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(3, 0) < 0.3


def test_summarise_reports_coverage_and_verdicts():
    rows = [{'id': 'A'}, {'id': 'B'}, {'id': 'C'}]
    labels = {'A': 'likely_true', 'B': 'likely_true', 'C': 'likely_true'}
    verdicts = {
        'A': {'verdict': 'likely_true', 'confidence': 0.9},
        'B': {'verdict': 'likely_false', 'confidence': 0.8},  # discordant → b
    }
    out = summarise(rows, verdicts, labels)
    assert out['total_samples'] == 3
    assert out['triaged_count'] == 2
    assert out['coverage'] == round(2/3, 4)
    assert out['mcnemar_b'] == 1 and out['mcnemar_c'] == 0
    assert out['mcnemar_exact_p'] == 1.0
    assert out['verdict_distribution']['likely_true'] == 1
