"""Model advisory failures must never turn a valid audit into 'failed'."""
import shutil
from pathlib import Path

import pytest

from localguard.config import Config
from localguard.model import ModelUnavailable
from localguard.registry import ToolRegistry

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'


@pytest.mark.anyio
async def test_malformed_warning_translation_keeps_audit_completed(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    root.mkdir()
    for file in FIXTURES.glob('vulnerable.*'):
        shutil.copyfile(file, root / file.name)
    cfg = Config(allowed_roots=[root], data_dir=tmp_path / 'state', model_tier='8gb')
    registry = ToolRegistry(cfg)
    # Force the model to emit a malformed warning-translation response; the
    # advisory boundary must log a downgrade and still complete the audit.
    async def broken(*args, **kwargs):
        raise ModelUnavailable('Warning explanation response malformed: IndexError: list index out of range')
    monkeypatch.setattr(type(registry.get_model()), 'explain_warnings', broken)
    # Make one scanner unavailable so a coverage warning exists to translate.
    from localguard import scanners as scanners_mod
    real_run = scanners_mod.run_scanner
    async def partly_unavailable(scanner, *args, **kwargs):
        if scanner == 'gitleaks':
            out = await real_run(scanner, *args, **kwargs)
            out['status'] = 'unavailable'
            out['warnings'] = ['fixture: forced unavailable for advisory test']
            return out
        return await real_run(scanner, *args, **kwargs)
    monkeypatch.setattr(scanners_mod, 'run_scanner', partly_unavailable)
    try:
        queued = await registry.call('audit_repository',
            {'target': str(root), 'scanners': ['patterns', 'gitleaks'],
             'include_dependencies': False, 'model_tier': '8gb'},
            'advisory-test', 'test')
        aid = queued['data']['audit_id']
        for _ in range(40):
            status = await registry.call('get_audit_status',
                {'audit_id': aid, 'wait_seconds': 1, 'limit': 200}, 'advisory-test')
            if status['data']['status'] in ('completed', 'failed'):
                break
        data = status['data']
        assert data['status'] == 'completed', data.get('error')
        assert len(data['issues']) >= 38  # deterministic findings retained
        assert any('unavailable' in w.lower() for w in data['warnings'])
    finally:
        await registry.close()
