from localguard.reporting import reorder_by_feedback


def issue(iid, severity='medium', feedback=None):
    return {'id': iid, 'severity': severity, 'confidence': 0.8,
            'feedback': feedback or {}}


def test_feedback_demotes_without_removing_or_changing():
    issues = [
        issue('A', 'low', {'rule_confirmed': 0, 'rule_false_positive': 3}),
        issue('B', 'low'),
        issue('C', 'low'),
    ]
    out = reorder_by_feedback(issues)
    assert len(out) == 3
    assert [i['id'] for i in out] == ['B', 'A', 'C']
    assert all(i['severity'] == 'low' for i in out)


def test_high_severity_never_demoted():
    issues = [
        issue('HIGH', 'high', {'rule_confirmed': 0, 'rule_false_positive': 9}),
        issue('LOW', 'low'),
    ]
    assert [i['id'] for i in reorder_by_feedback(issues)] == ['HIGH', 'LOW']


def test_demote_is_bounded():
    issues = [issue('FP', 'info', {'rule_confirmed': 0, 'rule_false_positive': 99})] + [
        issue(f'N{i}', 'info') for i in range(5)
    ]
    out = reorder_by_feedback(issues)
    assert out.index(next(i for i in out if i['id'] == 'FP')) == 1  # capped at 2 rank steps


def test_confirmed_beats_false_positive():
    issues = [
        issue('MIX', 'low', {'rule_confirmed': 4, 'rule_false_positive': 2}),
        issue('PLAIN', 'low'),
    ]
    assert [i['id'] for i in reorder_by_feedback(issues)] == ['MIX', 'PLAIN']
