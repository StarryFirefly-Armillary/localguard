"""Model triage verdicts are advisory: they must NOT change finding order.

Security regression: a high-confidence likely_true FALSE POSITIVE used to be
promoted to the top of the list (penalty sort), and a likely_false verdict
could demote a genuine high-severity finding. Deterministic risk order must
win; the verdict stays as a badge / log / filter aid only.
"""
import shutil
from pathlib import Path

import pytest

from localguard.config import Config
from localguard.registry import ToolRegistry

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'


def _severity_rank(issue):
    return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(issue['severity'], 9)


@pytest.mark.anyio
async def test_triage_verdict_does_not_reorder_findings(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    root.mkdir()
    for file in FIXTURES.glob('vulnerable.*'):
        shutil.copyfile(file, root / file.name)
    cfg = Config(allowed_roots=[root], data_dir=tmp_path / 'state', model_tier='8gb')
    registry = ToolRegistry(cfg)
    model = registry.get_model()
    # Capture the deterministic order the model was given, then flip EVERY
    # verdict to try to force a reorder: last finding -> likely_true,
    # first finding -> likely_false. Neither may change the final order.
    seen_ids = []

    async def adversarial_explain(self, records, tier='8gb', triage=False, conservative=False, **kwargs):
        seen_ids.extend(r['id'] for r in records)
        out = {}
        for i, r in enumerate(records):
            verdict = 'likely_false' if i == 0 else 'likely_true'
            out[r['id']] = {'explanation': 'e', 'remediation': 'r',
                            'verdict': verdict, 'confidence': 0.99,
                            'reason': 'adversarial test'}
        return out

    monkeypatch.setattr(type(model), 'explain_issues', adversarial_explain)
    try:
        queued = await registry.call('audit_repository',
            {'target': str(root), 'scanners': ['patterns'],
             'include_dependencies': False, 'model_tier': '8gb',
             'model_triage': True},
            'order-test', 'test')
        aid = queued['data']['audit_id']
        for _ in range(40):
            status = await registry.call('get_audit_status',
                {'audit_id': aid, 'wait_seconds': 1, 'limit': 200}, 'order-test')
            if status['data']['status'] in ('completed', 'failed'):
                break
        data = status['data']
        assert data['status'] == 'completed', data.get('error')
        issues = data['issues']
        assert len(issues) >= 2
        # Final order must stay deterministic by severity -> confidence -> path/line/id.
        keys = [(_severity_rank(i), -i['confidence'],
                 i['locations'][0]['path'], i['locations'][0]['line'], i['id'])
                for i in issues]
        assert keys == sorted(keys), 'triage verdict changed the deterministic order'
        # verdict still recorded on the issue, and audit log still has triage.
        triaged = [i for i in issues if i.get('triage')]
        assert triaged, 'triage verdicts must remain on issues as advisory badges'
        assert triaged[0]['triage']['verdict'] in ('likely_true', 'likely_false')
        assert any('likely_false' in (i.get('triage') or {}).get('verdict', '')
                   for i in issues), 'adversarial likely_false must still be recorded'
    finally:
        await registry.close()
