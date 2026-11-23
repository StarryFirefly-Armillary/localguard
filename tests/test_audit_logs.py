"""Incremental audit log console: session-scoped, machine-readable events."""
import pytest

from localguard.config import Config
from localguard.registry import ToolRegistry
from localguard.storage import Store
from localguard.web import create_app


def test_recent_logs_filters_by_audit_and_incremental_cursor(tmp_path):
    (tmp_path / 'state').mkdir()
    store = Store(tmp_path / 'state')
    store.log(event='tool_call', audit_id='A', tool_name='audit_repository', validation='passed')
    store.log(event='scanner_completed', audit_id='A', scanner='patterns', status='completed', findings=5, progress=30)
    store.log(event='tool_call', audit_id='A', tool_name='get_audit_status', validation='passed')  # UI noise
    store.log(event='tool_evidence', audit_id='A', summary='x')
    store.log(event='audit_failed', audit_id='A', error='boom')
    store.log(event='tool_call', audit_id='B', tool_name='audit_repository', validation='passed')

    logs = store.recent_logs('A')
    assert [e['event'] for e in logs] == ['tool_call', 'scanner_completed', 'audit_failed']
    assert any('patterns' in e['message'] for e in logs)
    assert all(e['level'] in ('info', 'warn', 'error') for e in logs)
    assert next(e for e in logs if e['event'] == 'audit_failed')['level'] == 'error'
    assert all('summary' not in str(e) for e in logs)  # tool_evidence excluded

    since = logs[0]['id']
    assert [e['event'] for e in store.recent_logs('A', since_id=since)] == ['scanner_completed', 'audit_failed']


@pytest.mark.anyio
async def test_logs_route_is_session_scoped(tmp_path):
    config = Config(allowed_roots=[tmp_path], data_dir=tmp_path / 'state')
    from starlette.testclient import TestClient
    app = create_app(config)
    registry = app.state.registry
    with TestClient(app) as client:
        boot = client.get('/api/bootstrap').json()
        headers = {'x-csrf-token': boot['csrf_token']}
        sid = boot['session_id']
        mine = registry.store.enqueue(sid, {'target': str(tmp_path)})
        registry.store.log(event='tool_call', audit_id=mine['audit_id'], tool_name='audit_repository')
        ok = client.get(f"/api/audits/{mine['audit_id']}/logs", headers=headers)
        assert ok.status_code == 200
        assert any(e['event'] == 'tool_call' for e in ok.json()['logs'])
        # A foreign session cannot read this audit's logs: call store.get
        # directly with a different session to verify ownership isolation.
        from localguard.paths import BoundaryError
        with pytest.raises(ValueError, match='Unknown audit_id'):
            registry.store.get(mine['audit_id'], 'foreign-session')
