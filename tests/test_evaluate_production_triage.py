"""Production triage evaluator must separate coverage from quality."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from evaluate_production_triage import (
    _metrics, _field_completeness, _field_completeness_from_presence, _is_placeholder,
    _server_process, OUTPUT_FIELDS, PLACEHOLDER_EXPLANATION, PLACEHOLDER_REMEDIATION)


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
    assert m['triaged_samples'] == 6 and m['missing_verdict'] == 2
    assert m['conditional_precision'] == round(2 / 5, 4)
    assert m['conditional_fpr'] == 0.75  # 3 fp / 4 judged negatives
    assert m['all_negative_false_positive'] == 0.6  # 3 fp / 5 negatives
    assert m['all_negative_abstention'] == 0.2
    assert 'conditional_fpr' in m and 'all_negative_false_positive' in m


def test_positive_and_negative_coverage_separated():
    rows = [_row('likely_true', 'likely_true'), _row('likely_true', None),
            _row('likely_false', None), _row('likely_false', None)]
    m = _metrics(rows)
    assert m['positive_coverage'] == 0.5
    assert m['negative_coverage'] == 0.0
    assert m['negative_abstention'] == 1.0
    assert m['verdict_completeness'] == 0.25


def test_all_sample_recall_does_not_hide_abstained_positives():
    # Regression: conditional_recall could read 100% while a real positive was
    # skipped. Safety view must include abstentions in the denominator.
    rows = [_row('likely_true', 'likely_true'), _row('likely_true', None)]
    m = _metrics(rows)
    assert m['conditional_recall'] == 1.0  # 1 caught / 1 triaged
    assert m['all_sample_recall'] == 0.5    # 1 caught / 2 REAL positives
    assert m['positive_abstention'] == 0.5
    assert m['all_sample_false_negative'] == 1


def test_uncertain_denominator_is_triaged_subset():
    rows = [_row('likely_true', 'uncertain'), _row('likely_false', 'uncertain'),
            _row('likely_true', None)]
    m = _metrics(rows)
    assert m['uncertain'] == 2 and m['uncertain_rate'] == 1.0
    assert m['conditional_precision'] is None


def test_field_completeness_calls_the_real_aggregator():
    # Regression: old inline code iterated field_stats (with 'all_fields' key)
    # so all() always failed. Test the REAL function used by run().
    full = {'explanation': 'e', 'remediation': 'r', 'verdict': 'likely_true',
            'confidence': 0.7, 'reason': 'why'}
    partial = dict(full, reason='')
    stats = _field_completeness([full, partial])
    assert stats == {'explanation': 2, 'remediation': 2, 'verdict': 2,
                     'confidence': 2, 'reason': 1, 'all_fields': 1}
    assert stats['all_fields'] == 1  # would be 0 under the old bug
    assert 'all_fields' not in OUTPUT_FIELDS


def test_placeholder_identification_calls_real_function():
    ph = {'explanation': PLACEHOLDER_EXPLANATION, 'remediation': PLACEHOLDER_REMEDIATION,
          'verdict': None}
    real = {'explanation': 'real explanation', 'remediation': 'real fix', 'verdict': 'likely_true'}
    # missing triage fields but real explanation is NOT a placeholder
    no_verdict = {'explanation': 'real explanation', 'remediation': 'real fix', 'verdict': None}
    assert _is_placeholder(ph) is True
    assert _is_placeholder(real) is False
    assert _is_placeholder(no_verdict) is False  # distinguishes the two production paths


def test_presence_based_recompute_for_presence_only_artifacts():
    # Regression: a corrected artifact declared _field_completeness(per_sample)
    # was valid, but per_sample has only *_present booleans -> returns 0.
    full = _row('likely_true', 'likely_true')
    partial = _row('likely_true', 'likely_true', reason='')
    presence = [{f'{k}_present': item.get(k) not in (None, '') for k in OUTPUT_FIELDS}
                for item in (full, partial)]
    stats = _field_completeness_from_presence(presence)
    assert stats == {'explanation': 2, 'remediation': 2, 'verdict': 2,
                     'confidence': 2, 'reason': 1, 'all_fields': 1}
    # both functions agree when an item has both values and presence flags
    assert stats == _field_completeness([full, partial])


def test_server_process_parses_port_from_endpoint_with_url_path(monkeypatch):
    # Regression: endpoint 'http://127.0.0.1:17865/v1' used to be parsed by
    # int(endpoint.rsplit(':', 1)[-1]) -> '17865/v1' -> ValueError, so the
    # observed PID/command line was never captured.
    calls = []

    def fake_check_output(cmd, **kwargs):
        calls.append(cmd)
        return '12345\n' if 'Get-NetTCPConnection' in ' '.join(cmd) else 'llama-server.exe --model x'

    monkeypatch.setattr('evaluate_production_triage.subprocess.check_output',
                        fake_check_output)
    info = _server_process('http://127.0.0.1:17865/v1')
    assert info['observed'] is True and info['pid'] == 12345
    assert '17865' in ' '.join(calls[0])
    assert 'invalid literal' not in str(info.get('note'))


def test_server_process_endpoint_without_path_and_missing_port(monkeypatch):
    calls = []

    def fake_check_output(cmd, **kwargs):
        calls.append(cmd)
        return '777\n'

    monkeypatch.setattr('evaluate_production_triage.subprocess.check_output',
                        fake_check_output)
    ok = _server_process('http://127.0.0.1:9999')
    assert ok['pid'] == 777 and '9999' in ' '.join(calls[0])
    calls.clear()
    missing = _server_process('http://127.0.0.1')
    assert missing['observed'] is False and not calls
    assert 'no port' in str(missing['note'])
