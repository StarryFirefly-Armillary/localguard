"""AI explanation budget: only top-N findings get AI prose; no finding is
removed, no severity changes, every deterministic evidence chain survives."""
import json
from pathlib import Path

import pytest

from localguard.config import Config
from localguard.registry import ToolRegistry


@pytest.mark.anyio
@pytest.mark.parametrize('limit,expected', [(3, 3), (0, 'all')])
async def test_explanation_budget_caps_model_calls_only(tmp_path, monkeypatch, limit, expected):
    root = tmp_path / 'repo'
    root.mkdir()
    import shutil
    fixtures = Path(__file__).resolve().parents[1] / 'fixtures'
    for file in fixtures.glob('vulnerable.*'):
        shutil.copyfile(file, root / file.name)
    config = Config(allowed_roots=[root], data_dir=tmp_path / 'state',
                    model_tier='8gb', max_model_explanations=limit)
    registry = ToolRegistry(config)
    seen = []

    async def fake_explain(records, tier, triage=False):
        seen.append(records)
        return {r['id']: {'explanation': 'AI 解释', 'remediation': '修复建议',
                          'verdict': 'likely_true', 'confidence': 0.9, 'reason': '测试'}
                for r in records}

    monkeypatch.setattr(registry.get_model(), 'explain_issues', fake_explain)
    queued = registry.store.enqueue('s', {'target': str(root), 'scanners': ['patterns'],
                                          'include_dependencies': False, 'model_tier': '8gb',
                                          'max_explanations': limit})
    try:
        await registry.engine.execute(registry.store.claim())
        result = registry.store.get(queued['audit_id'], 's')
        issues = result['issues']
        assert result['status'] == 'completed', result.get('error')
        assert seen, 'model was never called'
        called = len(seen[0])
        if expected == 'all':
            assert called == len(issues)
            assert all(i.get('ai_explanation') == 'done' for i in issues)
        else:
            assert called == expected
            done = [i for i in issues if i.get('ai_explanation') == 'done']
            skipped = [i for i in issues if i.get('ai_explanation') == 'skipped_budget']
            assert len(done) == expected
            assert skipped
            # Skipped findings keep full deterministic evidence + severity.
            for issue in skipped:
                assert issue['locations'] and issue['locations'][0]['snippet_hash']
                assert issue['evidence']
                assert issue['severity'] in ('critical', 'high', 'medium', 'low', 'info')
    finally:
        await registry.close()


def test_config_bounds_explanation_count(tmp_path):
    with pytest.raises(ValueError, match='max_model_explanations'):
        Config(allowed_roots=[tmp_path], data_dir=tmp_path / 'state', max_model_explanations=-1)
    with pytest.raises(ValueError, match='max_model_explanations'):
        Config(allowed_roots=[tmp_path], data_dir=tmp_path / 'state', max_model_explanations=501)
