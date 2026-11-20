import json
from pathlib import Path
from types import SimpleNamespace

from mcp.types import CallToolResult,TextContent
import pytest

from localguard.config import Config
from localguard.paths import BoundaryError,PathPolicy
from localguard.registry import ToolRegistry
from localguard.reporting import from_finding
from localguard.serialization import tool_text


def make_registry(tmp_path):
    root = tmp_path/'repo'
    root.mkdir()
    return ToolRegistry(Config(allowed_roots=[root],data_dir=tmp_path/'state'))


def test_discovery_cannot_trust_repo_path(tmp_path,monkeypatch):
    root = tmp_path/'repo'
    root.mkdir()
    evil = root/'semgrep.exe'
    evil.write_bytes(b'not executed')
    monkeypatch.chdir(root)
    monkeypatch.setenv('PATH',str(root))
    config = Config(allowed_roots=[root],data_dir=tmp_path/'state')
    assert 'semgrep' not in config.binaries


def test_git_metadata_pointer_includes_and_alternates(tmp_path):
    root = tmp_path/'allowed'
    outside = tmp_path/'outside'
    root.mkdir()
    outside.mkdir()
    policy = PathPolicy([root])
    (root/'.git').write_text('gitdir: '+str(outside))
    with pytest.raises(BoundaryError,match='outside'):
        policy.git_metadata(root)
    (root/'.git').unlink()
    (root/'.git').mkdir()
    config = root/'.git'/'config'
    config.write_text('[include]\npath = '+str(outside/'private'))
    with pytest.raises(BoundaryError,match='includes'):
        policy.git_metadata(root)
    config.write_text('[core]\nbare = false\n')
    info = root/'.git'/'objects'/'info'
    info.mkdir(parents=True)
    (info/'alternates').write_text(str(outside))
    with pytest.raises(BoundaryError,match='alternate'):
        policy.git_metadata(root)


def test_managed_clone_contents_not_excluded(tmp_path):
    registry = make_registry(tmp_path)
    clone = registry.config.data_dir/'repositories'/'clone'
    clone.mkdir(parents=True)
    (clone/'source.txt').write_text('source evidence\n')
    registry.policy.roots.append(clone)
    with registry.engine.snapshot(clone) as (snapshot,hashes,skipped):
        assert (snapshot/'source.txt').read_text()=='source evidence\n'
        assert 'source.txt' in hashes
        assert not skipped


def test_worker_configuration_binding(tmp_path):
    one = tmp_path/'one'
    two = tmp_path/'two'
    one.mkdir()
    two.mkdir()
    a = ToolRegistry(Config(allowed_roots=[one],data_dir=tmp_path/'shared'))
    b = ToolRegistry(Config(allowed_roots=[two],data_dir=tmp_path/'shared'))
    queued = a.store.enqueue('session',{'target':str(one)})
    assert b.store.claim() is None
    assert a.store.claim()['id']==queued['audit_id']


@pytest.mark.anyio
async def test_impossible_resource_estimate_rejected(tmp_path,monkeypatch):
    import psutil
    registry = make_registry(tmp_path)
    monkeypatch.setattr(psutil,'virtual_memory',lambda:SimpleNamespace(total=8*1024**3,available=4*1024**3))
    result = await registry.call('audit_repository',{'target':str(registry.config.allowed_roots[0]),'resource_estimate':{'ram_mb':32768}},'s')
    assert result['isError']
    assert 'RAM' in result['error']
    assert registry.store.claim() is None


@pytest.mark.anyio
async def test_actual_serialized_mcp_budget_and_read_range(tmp_path):
    registry = make_registry(tmp_path)
    file = registry.config.allowed_roots[0]/'quotes.txt'
    file.write_text(('"\\'*600+'\n')*100)
    result = await registry.call('view_file',{'path':str(file),'start_line':1,'end_line':100},'s')
    assert not result['isError']
    data = result['data']
    wire = CallToolResult(isError=False,structuredContent=data,content=[TextContent(type='text',text=tool_text(data))]).model_dump_json(exclude_none=True).encode()
    assert len(wire)<=registry.config.max_output_bytes
    assert data['truncated']
    assert registry.store.latest('s',file)['end']==data['lines'][-1]['line']


@pytest.mark.anyio
async def test_warning_truncation_preserves_issue_progress(tmp_path):
    registry = make_registry(tmp_path)
    root = registry.config.allowed_roots[0]
    file = root/'a.txt'
    file.write_text('sample\n')
    queued = registry.store.enqueue('s',{'target':str(root)})
    issue = from_finding({'path':'a.txt','line':1,'title':'Example','severity':'high','category':'other','cwe':'CWE-20','tool':'patterns','rule_id':'r'},'sample')
    queued.update(status='completed',root=str(root),issues=[issue],warnings=['x'*5000]*100)
    registry.store.update(queued['audit_id'],queued)
    result = await registry.call('get_audit_status',{'audit_id':queued['audit_id']},'s')
    assert not result['isError'],result
    assert len(result['data']['issues'])==1
    assert result['data']['total_issues']==1
    assert 'next_offset' not in result['data']
    assert result['data']['truncated']
