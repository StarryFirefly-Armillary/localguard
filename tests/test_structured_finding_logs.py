"""Minimal structured identity fields on finding-level audit logs.

Pure unit tests for field extraction plus a rules-only audit integration check
(no model): human_review and model-triage-capable logs carry identifiers and
coordinates, never source text or secret values.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from localguard.config import Config
from localguard.engine import finding_log_fields
from localguard.registry import ToolRegistry
from localguard.schemas import rule_id_from_evidence

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'
FIELDS = ('issue_id', 'rule_id', 'scanner', 'path', 'line', 'engine')


async def rules_audit(registry, root):
    q = await registry.call('audit_repository',
        {'target': str(root), 'scanners': ['patterns'], 'include_dependencies': False,
         'model_tier': 'rules', 'model_triage': False}, 'test', 'test')
    assert not q['isError'], q
    for _ in range(40):
        st = await registry.call('get_audit_status',
             {'audit_id': q['data']['audit_id'], 'wait_seconds': 1, 'limit': 200}, 'test')
        if st['data']['status'] in ('completed', 'failed'):
            assert st['data']['status'] == 'completed', st
            return st['data']
    raise AssertionError('Audit did not finish')


def test_finding_log_fields_are_identifiers_only():
    issue = {'id': 'ISSUE-1', 'locations': [{'path': 'src/app.py', 'line': 42}],
             'evidence': [{'tool': 'semgrep', 'rule_id': 'lg.ext.x'}]}
    context = {'rule_id': 'lg.ext.sql-injection', 'scanner': 'semgrep',
               'path': 'src/app.py', 'line': 42,
               'source': [{'line': 42, 'text': 'SECRET = "super-secret-value"'}]}
    out = finding_log_fields(issue, context)
    assert tuple(k for k in FIELDS if k in out) == FIELDS
    assert out['issue_id'] == 'ISSUE-1'
    assert out['rule_id'] == 'lg.ext.sql-injection'
    # engine is synonymous with scanner (detection engine), NOT model tier.
    assert out['scanner'] == 'semgrep' and out['engine'] == 'semgrep'
    assert out['path'] == 'src/app.py' and out['line'] == 42
    assert 'model_tier' not in out
    blob = json.dumps(out, ensure_ascii=False)
    assert 'super-secret' not in blob and 'SECRET' not in blob


def test_finding_log_fields_prefers_context_then_evidence():
    # No context: rule_id/scanner must come from evidence, not raw_ref.
    issue = {'id': 'I-2', 'locations': [{'path': 'a.py', 'line': 7}],
             'evidence': [{'tool': 'patterns', 'rule_id': 'patterns.reverse-shell',
                           'raw_ref': '#/results/66'}]}
    out = finding_log_fields(issue, None)
    assert out['rule_id'] == 'patterns.reverse-shell'
    assert out['scanner'] == 'patterns' and out['engine'] == 'patterns'
    # Context wins over evidence when both present.
    ctx = {'rule_id': 'lg.ext.ctx-rule', 'scanner': 'semgrep'}
    assert finding_log_fields(issue, ctx)['rule_id'] == 'lg.ext.ctx-rule'


def test_finding_log_fields_best_effort_and_no_json_pointer_as_rule():
    empty = finding_log_fields({}, None)
    assert all(empty.get(k) is None for k in FIELDS)
    issue = {'id': 'I-3', 'locations': [{'path': 'a.py', 'line': 7}],
             'evidence': [{'raw_ref': '#/results/66'}]}
    out = finding_log_fields(issue, {})
    assert out['rule_id'] is None  # JSON pointer is NOT a rule id
    assert out['scanner'] is None and out['engine'] is None
    assert out['path'] == 'a.py' and out['line'] == 7


def test_legacy_raw_ref_rule_id_is_attributed():
    # Legacy issue: no evidence.rule_id, raw_ref IS the real rule id.
    legacy = {'tool': 'patterns', 'raw_ref': 'patterns.reverse-shell'}
    assert rule_id_from_evidence(legacy) == 'patterns.reverse-shell'
    issue = {'id': 'I-legacy', 'locations': [{'path': 'a.c', 'line': 4}],
             'evidence': [legacy]}
    assert finding_log_fields(issue, {})['rule_id'] == 'patterns.reverse-shell'


def test_json_pointer_raw_ref_is_never_a_rule_id():
    pointer = {'tool': 'semgrep', 'raw_ref': '#/results/66'}
    assert rule_id_from_evidence(pointer) is None
    issue = {'id': 'I-pointer', 'locations': [{'path': 'a.py', 'line': 9}],
             'evidence': [pointer]}
    assert finding_log_fields(issue, {})['rule_id'] is None
    # Explicit rule_id in new evidence still wins over a pointer raw_ref.
    both = {'tool': 'semgrep', 'rule_id': 'lg.ext.x', 'raw_ref': '#/results/66'}
    assert rule_id_from_evidence(both) == 'lg.ext.x'


@pytest.mark.anyio
async def test_human_review_log_has_structured_identity(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    shutil.copyfile(FIXTURES / 'vulnerable.py', root / 'vulnerable.py')
    registry = ToolRegistry(Config(allowed_roots=[root], data_dir=tmp_path / 'state',
                                   model_tier='rules'))
    try:
        report = await rules_audit(registry, root)
        issue = report['issues'][0]
        registry.store.review(report['audit_id'], 'test', issue['id'], 'confirmed')
        with registry.store.connect() as db:
            events = [json.loads(p) for (p,) in db.execute('SELECT payload FROM logs').fetchall()]
        review = [e for e in events if e.get('event') == 'human_review'
                  and e.get('issue_id') == issue['id']]
        assert review, 'human_review must be logged'
        e = review[-1]
        assert e['decision'] == 'confirmed'
        assert all(k in e for k in FIELDS)
        assert e['issue_id'] == issue['id']
        # Concrete values, not just key presence: real dotted rule id and a
        # non-empty scanner. A JSON pointer must NEVER be used as rule_id.
        assert e['rule_id'] and '.' in str(e['rule_id'])
        assert not str(e['rule_id']).startswith('#/results/')
        assert e['scanner'] in ('patterns', 'semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype')
        assert e['engine'] == e['scanner']
        assert e['path'] == issue['locations'][0]['path']
        assert e['line'] == issue['locations'][0]['line']
        assert 'source' not in e and 'secret' not in json.dumps(e).lower()
    finally:
        await registry.close()


@pytest.mark.anyio
async def test_model_triage_verdicts_carry_structured_issue_identity(tmp_path, monkeypatch):
    from localguard.model import PLACEHOLDER_EXPLANATION, PLACEHOLDER_REMEDIATION
    root = tmp_path / 'repo'
    root.mkdir()
    for f in FIXTURES.glob('vulnerable.*'):
        shutil.copyfile(f, root / f.name)
    registry = ToolRegistry(Config(allowed_roots=[root], data_dir=tmp_path / 'state',
                                   model_tier='8gb'))
    model = registry.get_model()

    async def fake(self, records, tier='8gb', triage=False, **kw):
        out = {}
        for r in records:
            base = ({'explanation': PLACEHOLDER_EXPLANATION,
                     'remediation': PLACEHOLDER_REMEDIATION}
                    if not triage else
                    {'explanation': 'e', 'remediation': 'r', 'verdict': 'likely_true',
                     'confidence': 0.9, 'reason': 'fixture reason'})
            out[r['id']] = base
        return out
    monkeypatch.setattr(type(model), 'explain_issues', fake)
    try:
        q = await registry.call('audit_repository',
            {'target': str(root), 'scanners': ['patterns'], 'include_dependencies': False,
             'model_tier': '8gb', 'model_triage': True}, 'log-test', 'test')
        aid = q['data']['audit_id']
        for _ in range(40):
            st = await registry.call('get_audit_status',
                 {'audit_id': aid, 'wait_seconds': 1, 'limit': 200}, 'log-test')
            if st['data']['status'] in ('completed', 'failed'):
                break
        with registry.store.connect() as db:
            events = [json.loads(p) for (p,) in db.execute('SELECT payload FROM logs').fetchall()]
        triage = [e for e in events if e.get('event') == 'model_triage' and e.get('audit_id') == aid]
        assert triage, 'model_triage event must be logged'
        verdicts = [v for e in triage for v in e.get('verdicts', [])]
        assert verdicts, 'verdicts must be present'
        for v in verdicts:
            assert all(k in v for k in FIELDS), v
            assert v['issue_id'] and v['verdict'] in ('likely_true', 'likely_false')
            # Detection engine, not the model tier; tier is a separate field.
            assert v['scanner'] in ('patterns', 'semgrep', 'gitleaks', 'gosec', 'cppcheck', 'pip-audit', 'grype')
            assert v['engine'] == v['scanner']
            assert v['rule_id'] and not str(v['rule_id']).startswith('#/results/')
            assert v['model_tier'] == '8gb'
    finally:
        await registry.close()
