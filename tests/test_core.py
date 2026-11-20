import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from localguard.config import Config
from localguard.paths import BoundaryError,PathPolicy
from localguard.registry import ToolRegistry
from localguard.reporting import EvidenceError,export_report,from_finding,rank
from localguard.schemas import TOOLS


@pytest.fixture
def registry(tmp_path):
    root = tmp_path/'repo'
    root.mkdir()
    return ToolRegistry(Config(allowed_roots=[root],data_dir=tmp_path/'state'))


def source(registry,text='first\nsecond\nthird\n'):
    file = registry.config.allowed_roots[0]/'source.txt'
    file.write_text(text,encoding='utf-8')
    return file


def issue(file,text='second',line=2):
    return from_finding({'path':file.name,'line':line,'title':'Test finding','severity':'high','category':'other',
                         'cwe':'CWE-20','tool':'patterns','rule_id':'test-rule'},text)


@pytest.mark.anyio
async def test_real_line_index_and_validation(registry):
    file = source(registry)
    result = await registry.call('view_file',{'path':str(file),'start_line':2,'end_line':3},'session')
    assert not result['isError']
    assert result['data']['lines'][0] == {'line':2,'text':'second','tokens':[]}
    report = registry.rank_and_report([issue(file)],'session',file.parent)
    assert report['issues'][0]['locations'][0]['line']==2
    assert report['issues'][0]['evidence'][-1]['range']==[2,3]


@pytest.mark.anyio
async def test_reject_unread_outside_range_stale_and_wrong_hash(registry):
    file = source(registry)
    for session,reason in [('new','Unread')]:
        with pytest.raises(EvidenceError,match=reason):
            registry.rank_and_report([issue(file)],session,file.parent)
    await registry.call('view_file',{'path':str(file),'start_line':1,'end_line':1},'s')
    with pytest.raises(EvidenceError,match='outside'):
        registry.rank_and_report([issue(file)],'s',file.parent)
    await registry.call('view_file',{'path':str(file)},'s')
    with pytest.raises(EvidenceError,match='snippet_hash'):
        registry.rank_and_report([issue(file,'wrong')],'s',file.parent)
    changed = issue(file)
    file.write_text('first\nchanged\nthird\n')
    with pytest.raises(EvidenceError,match='Stale'):
        registry.rank_and_report([changed],'s',file.parent)
    assert changed['locations'][0]['stale']
    with registry.store.connect() as db:
        logs = [json.loads(row[0]) for row in db.execute('SELECT payload FROM logs')]
    assert sum(log.get('event')=='location_rejected' for log in logs)==4


@pytest.mark.anyio
async def test_schema_and_path_boundary_and_internal_tool(registry,tmp_path):
    file = source(registry)
    for name,args in [
        ('view_file',{'path':str(file.parent/'..'/'repo'/'source.txt')}),
        ('view_file',{'path':'relative.txt'}),
        ('view_file',{'path':str(tmp_path/'outside.txt')}),
        ('view_file',{'path':str(file),'start_line':0}),
        ('run_scanner',{'target':str(file.parent),'scanner':'cmd.exe'}),
        ('run_scanner',{'target':str(file.parent),'scanner':'patterns','ruleset':'../../evil.yml'}),
        ('audit_repository',{'target':str(file.parent),'depth':'arbitrary'}),
        ('rank_and_report',{'issues':[]})
    ]:
        result = await registry.call(name,args,'s','security-test')
        assert result['isError'],(name,args)
        assert 'Traceback' not in result['error']
    outside = tmp_path/'secret.txt'
    outside.write_text('not readable')
    link = file.parent/'escape.txt'
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip('Symlink creation needs Windows Developer Mode')
    result = await registry.call('view_file',{'path':str(link)},'s')
    assert result['isError']


@pytest.mark.anyio
async def test_output_budget_and_latest_actual_range(registry):
    file = source(registry,('\u4e2d'*1000+'\n')*100)
    result = await registry.call('view_file',{'path':str(file),'start_line':1,'end_line':100},'s')
    assert not result['isError']
    data = result['data']
    assert data['truncated']
    assert len(json.dumps(result,ensure_ascii=False).encode())<registry.config.max_output_bytes
    assert registry.store.latest('s',file)['end']==data['lines'][-1]['line']


def test_schema_is_single_source(registry):
    tools = {t['name']:t for t in registry.describe()}
    assert 'rank_and_report' not in tools
    for name,tool in tools.items():
        assert tool['inputSchema']==TOOLS[name]['inputSchema']
        assert tool['outputSchema']==TOOLS[name]['outputSchema']
        assert len(tool['description'])>150
    assert tools['audit_repository']['outputSchema']['properties']['issues']['items']['properties']['locations']


def test_rank_and_exports(registry):
    file = source(registry)
    first = issue(file)
    second = deepcopy(first)
    second['evidence']=[{'tool':'semgrep','raw_ref':'rule'}]
    second['severity']='critical'
    result = rank([first,second])
    assert len(result)==1 and result[0]['severity']=='critical' and result[0]['needs_human_review']
    status = {'audit_id':'a'*32,'status':'completed','issues':result,'warnings':['gitleaks unavailable']}
    for format in ('json','markdown','sarif'):
        text,media,extension = export_report(status,format)
        assert text and media and extension
    sarif = json.loads(export_report(status,'sarif')[0])
    assert sarif['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine']==2


@pytest.mark.anyio
async def test_cross_instance_queue_and_session_isolation(registry):
    other = ToolRegistry(registry.config)
    one = registry.store.enqueue('a',{'target':str(registry.config.allowed_roots[0])})
    two = other.store.enqueue('b',{'target':str(registry.config.allowed_roots[0])})
    assert other.store.get(two['audit_id'],'b')['queue_position']==2
    first = registry.store.claim()
    assert first['id']==one['audit_id']
    assert other.store.claim() is None
    with pytest.raises(ValueError,match='Unknown'):
        other.store.get(one['audit_id'],'b')
    entered=[]
    async def task(number,store):
        async with store.resource():
            entered.append(number)
            await asyncio.sleep(0.05)
            entered.append(-number)
    await asyncio.gather(task(1,registry.store),task(2,other.store))
    assert entered==[1,-1,2,-2]
