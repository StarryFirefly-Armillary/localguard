from localguard.reporting import compare_baseline, issue_signature


def issue(iid, path='a.py', line=10, title='SQL injection', category='injection'):
    return {'id': iid, 'title': title, 'category': category,
            'locations': [{'path': path, 'line': line}]}


def test_compare_baseline_added_resolved_persisted():
    baseline = {'audit_id': 'OLD', 'issues': [issue('1'), issue('2', line=20)]}
    current = [issue('X'), issue('Y', line=20), issue('Z', line=30)]
    result = compare_baseline(current, baseline)
    assert result['baseline_audit_id'] == 'OLD'
    assert result['added'] == ['Z']
    assert result['resolved'] == []
    assert result['persisted'] == 2


def test_compare_baseline_ignores_volatile_ids():
    baseline = {'audit_id': 'OLD', 'issues': [issue('old-id')]}
    assert compare_baseline([issue('new-id')], baseline)['persisted'] == 1


def test_no_baseline_returns_none():
    assert compare_baseline([issue('1')], None) is None
    assert compare_baseline([issue('1')], {'issues': []}) is None


def test_signature_uses_path_line_title():
    assert issue_signature(issue('1')) == issue_signature(issue('2'))
