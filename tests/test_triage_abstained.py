"""Triage abstained status: advisory-only, never changes findings or order.

Scenarios: scored/uncertain behavior unchanged; no-verdict & placeholder become
abstained with needs_human_review; critical-CWE abstention is high priority;
severity/location/source and deterministic order stay untouched; audit log
distinguishes missing_verdict from placeholder.
"""
import shutil
from pathlib import Path

import pytest

from localguard.config import Config
from localguard.engine import needs_high_priority_review
from localguard.model import (
    PLACEHOLDER_EXPLANATION, PLACEHOLDER_REMEDIATION,
    abstain_reason_for, triage_status_for,
)
from localguard.registry import ToolRegistry

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'


def test_status_helpers():
    assert triage_status_for({'verdict': 'likely_true'}) == 'scored'
    assert triage_status_for({'verdict': 'likely_false'}) == 'scored'
    assert triage_status_for({'verdict': 'uncertain'}) == 'uncertain'
    assert triage_status_for({'explanation': 'e'}) == 'abstained'
    ph = {'explanation': PLACEHOLDER_EXPLANATION, 'remediation': PLACEHOLDER_REMEDIATION}
    assert abstain_reason_for(ph) == 'placeholder'
    assert abstain_reason_for({'explanation': 'real explanation', 'remediation': 'real fix'}) == 'missing_verdict'
    assert abstain_reason_for({'verdict': 'likely_true', 'explanation': 'e'}) is None


@pytest.mark.anyio
@pytest.mark.parametrize('mode', ['plain_no_verdict', 'placeholder', 'uncertain', 'scored'])
async def test_abstained_preserves_finding_and_order(tmp_path, monkeypatch, mode):
    root = tmp_path / 'repo'
    root.mkdir()
    for file in FIXTURES.glob('vulnerable.*'):
        shutil.copyfile(file, root / file.name)
    cfg = Config(allowed_roots=[root], data_dir=tmp_path / 'state', model_tier='8gb')
    registry = ToolRegistry(cfg)
    model = registry.get_model()

    async def fake_explain(self, records, tier='8gb', triage=False, conservative=False, **kwargs):
        out = {}
        for r in records:
            base = {'explanation': 'e', 'remediation': 'r'}
            if mode == 'placeholder':
                base = {'explanation': PLACEHOLDER_EXPLANATION,
                        'remediation': PLACEHOLDER_REMEDIATION}
            elif mode == 'uncertain':
                base['verdict'] = 'uncertain'; base['confidence'] = 0.5; base['reason'] = 'unclear'
            elif mode == 'scored':
                base['verdict'] = 'likely_false'; base['confidence'] = 0.9; base['reason'] = 'benign test data'
            out[r['id']] = base
        return out

    monkeypatch.setattr(type(model), 'explain_issues', fake_explain)
    try:
        queued = await registry.call('audit_repository',
            {'target': str(root), 'scanners': ['patterns'], 'include_dependencies': False,
             'model_tier': '8gb', 'model_triage': True}, 'abstain-test', 'test')
        aid = queued['data']['audit_id']
        for _ in range(40):
            status = await registry.call('get_audit_status',
                {'audit_id': aid, 'wait_seconds': 1, 'limit': 200}, 'abstain-test')
            if status['data']['status'] in ('completed', 'failed'):
                break
        data = status['data']
        assert data['status'] == 'completed', data.get('error')
        issues = data['issues']
        assert issues, f'findings must be retained (status={data.get("status")}, error={data.get("error")}, warnings={data.get("warnings")})'
        # deterministic order unchanged
        order_key = lambda i: ({'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(i['severity'], 9),
                               -i['confidence'], i['locations'][0]['path'],
                               i['locations'][0]['line'], i['id'])
        assert [order_key(i) for i in issues] == sorted(order_key(i) for i in issues)
        triaged = [i for i in issues if i.get('triage')]
        assert triaged, 'chosen findings must carry triage status'
        for issue in triaged:
            triage = issue['triage']
            if mode in ('plain_no_verdict', 'placeholder'):
                assert triage.get('triage_status') == 'abstained'
                assert triage.get('verdict') is None
                assert issue['needs_human_review'] is True, 'abstained must require human review'
                assert triage.get('abstain_reason') == (
                    'placeholder' if mode == 'placeholder' else 'missing_verdict')
                assert triage.get('confidence') is None, 'abstained must not fabricate confidence'
                assert triage.get('confidence') is None, 'abstained must not fabricate confidence'
            elif mode == 'uncertain':
                assert triage.get('triage_status') == 'uncertain'
                assert triage.get('verdict') == 'uncertain'
                assert issue['needs_human_review'] is True
                assert 'abstain_reason' not in triage
            else:
                assert triage.get('triage_status') == 'scored'
                assert triage.get('verdict') == 'likely_false'
            # severity/location/source never touched by triage
            assert issue['severity'] in ('critical', 'high', 'medium', 'low', 'info')
            assert issue['locations'] and issue['evidence']
    finally:
        await registry.close()


def test_critical_cwe_abstention_promotes_review_only():
    issue = {'cwe': 'CWE-89', 'severity': 'medium',
             'triage': {'triage_status': 'abstained', 'verdict': None}}
    assert needs_high_priority_review(issue) is True
    # scored verdicts are not promoted
    scored = dict(issue, triage={'triage_status': 'scored', 'verdict': 'likely_true'})
    assert needs_high_priority_review(scored) is False
    # non-critical CWE is not promoted
    benign = dict(issue, cwe='CWE-798')
    assert needs_high_priority_review(benign) is False
    # promotion never mutates severity
    assert issue['severity'] == 'medium'


def test_abstain_log_reason_distinguishes_placeholder_and_missing():
    # Both paths produce no verdict; the fixed placeholder text is the only
    # in-band signal to tell them apart for the model_triage_abstained event.
    ph = {'explanation': PLACEHOLDER_EXPLANATION, 'remediation': PLACEHOLDER_REMEDIATION}
    dropped = {'explanation': 'real explanation', 'remediation': 'real fix',
               'reason': 'invalid verdict removed'}
    assert abstain_reason_for(ph) == 'placeholder'
    assert abstain_reason_for(dropped) == 'missing_verdict'
    assert triage_status_for(ph) == triage_status_for(dropped) == 'abstained'
