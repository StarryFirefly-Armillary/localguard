import json

import pytest

from localguard.config import Config
from localguard.registry import ToolRegistry


@pytest.mark.anyio
@pytest.mark.parametrize('status', ['timeout', 'error', 'unavailable'])
async def test_scanner_failures_are_error_content_and_keep_diagnostics(tmp_path, monkeypatch, status):
    registry = ToolRegistry(Config(allowed_roots=[tmp_path], data_dir=tmp_path/'state'))
    async def scanner(*args, **kwargs):
        return {'scanner':'semgrep', 'status':status, 'findings':[], 'raw':None,
                'warnings':['Scanner unavailable or interrupted'], 'truncated':False}
    monkeypatch.setattr(registry.engine, 'scanner', scanner)
    result = await registry.call('run_scanner', {'scanner':'semgrep','target':str(tmp_path)}, 's', 'test-client')
    assert result['isError'] is True
    assert result['data']['status'] == status
    assert status in result['error']
    assert 'Traceback' not in result['error']
    with registry.store.connect() as db:
        log = json.loads(db.execute('SELECT payload FROM logs ORDER BY id DESC LIMIT 1').fetchone()[0])
    assert log['summary']['isError'] is True
    assert log['validation'] != 'passed'
    await registry.close()


@pytest.mark.anyio
async def test_valid_empty_scan_is_not_an_error(tmp_path, monkeypatch):
    registry = ToolRegistry(Config(allowed_roots=[tmp_path], data_dir=tmp_path/'state'))
    async def scanner(*args, **kwargs):
        return {'scanner':'semgrep','status':'completed','findings':[],'raw':{},'warnings':[],'truncated':False}
    monkeypatch.setattr(registry.engine,'scanner',scanner)
    result = await registry.call('run_scanner',{'scanner':'semgrep','target':str(tmp_path)},'s')
    assert result['isError'] is False
    await registry.close()
