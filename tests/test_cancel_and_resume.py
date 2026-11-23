"""Cancellation and reconnect support: a user must be able to stop an audit,
and a page reload must be able to rediscover the session's recent audits."""
import asyncio
import json

import pytest

from localguard.config import Config
from localguard.registry import ToolRegistry


@pytest.mark.anyio
async def test_cancel_running_audit_marks_cancelled_and_stops_task(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'sample.py').write_text('value = 1\n', encoding='utf-8')
    registry = ToolRegistry(Config(allowed_roots=[root], data_dir=tmp_path / 'state', model_tier='rules'))
    started = asyncio.Event()

    async def slow_scanner(*args, **kwargs):
        started.set()
        await asyncio.sleep(60)  # stand-in for a long semgrep run
        return {'scanner': 'semgrep', 'status': 'completed', 'findings': [], 'raw': None,
                'warnings': [], 'truncated': False, 'dropped_count': 0}

    monkeypatch.setattr('localguard.scanners.run_scanner', slow_scanner)
    queued = registry.store.enqueue('s', {'target': str(root), 'scanners': ['semgrep'],
                                          'include_dependencies': False, 'model_tier': 'rules'})
    audit_id = queued['audit_id']
    registry.engine.start()
    task = asyncio.create_task(registry.engine.execute(registry.store.claim()))
    registry.engine.active[audit_id] = task  # mirror what work() does
    try:
        await asyncio.wait_for(started.wait(), 5)
        out = registry.engine.cancel(audit_id, 's')
        assert out['status'] == 'cancelled'
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        stored = registry.store.get(audit_id, 's')
        assert stored['status'] == 'cancelled'
        assert stored['error'] and 'user' in stored['error'].lower()
    finally:
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await registry.close()


@pytest.mark.anyio
async def test_cancel_rejects_foreign_session_and_terminal_audit(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'sample.py').write_text('value = 1\n', encoding='utf-8')
    registry = ToolRegistry(Config(allowed_roots=[root], data_dir=tmp_path / 'state', model_tier='rules'))
    async def slow_scanner(*args, **kwargs):
        await asyncio.sleep(60)
        return {'scanner': 'semgrep', 'status': 'completed', 'findings': [], 'raw': None,
                'warnings': [], 'truncated': False, 'dropped_count': 0}
    monkeypatch.setattr('localguard.scanners.run_scanner', slow_scanner)
    queued = registry.store.enqueue('owner', {'target': str(root), 'scanners': ['semgrep'],
                                              'include_dependencies': False, 'model_tier': 'rules'})
    audit_id = queued['audit_id']
    with pytest.raises(ValueError, match='Unknown audit_id'):
        registry.engine.cancel(audit_id, 'stranger')  # session isolation

    # A terminal audit is returned unchanged, not re-cancelled.
    done = registry.store.enqueue('owner', {'target': str(root)})
    result = registry.store.get(done['audit_id'], 'owner')
    result.update(status='completed')
    registry.store.update(done['audit_id'], result)
    assert registry.engine.cancel(done['audit_id'], 'owner')['status'] == 'completed'
    await registry.close()


@pytest.mark.anyio
async def test_list_audits_is_session_scoped_and_omits_findings(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    registry = ToolRegistry(Config(allowed_roots=[root], data_dir=tmp_path / 'state', model_tier='rules'))
    mine = registry.store.enqueue('mine', {'target': str(root)})
    registry.store.enqueue('other', {'target': str(root)})
    out = await registry.call('list_audits', {'limit': 10}, 'mine', 'test-client')
    assert out['isError'] is False
    ids = [a['audit_id'] for a in out['data']['audits']]
    assert mine['audit_id'] in ids
    assert all('issues' not in a and 'findings' not in a for a in out['data']['audits'])
    await registry.close()
