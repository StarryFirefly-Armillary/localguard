import asyncio
import json
from pathlib import Path
import shutil

import pytest

from localguard.config import Config
from localguard.registry import ToolRegistry

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'


async def audit(registry,target,session='test'):
    queued = await registry.call('audit_repository',{'target':str(target),'scanners':['patterns'],'include_dependencies':False},session)
    assert not queued['isError'],queued
    assert queued['data']['status']=='queued'
    for _ in range(30):
        status = await registry.call('get_audit_status',{'audit_id':queued['data']['audit_id'],'wait_seconds':1,'limit':200},session)
        assert not status['isError'],status
        if status['data']['status'] in ('completed','failed'):
            assert status['data']['status']=='completed',status
            return status['data']
    raise AssertionError('Audit did not finish')


@pytest.mark.anyio
async def test_exact_multilingual_findings_reproducibility_and_stale(tmp_path):
    root = tmp_path/'repo'
    root.mkdir()
    for file in FIXTURES.glob('vulnerable.*'):
        shutil.copyfile(file,root/file.name)
    registry = ToolRegistry(Config(allowed_roots=[root],data_dir=tmp_path/'state',model_tier='rules'))
    try:
        first = await audit(registry,root)
        second = await audit(registry,root)
        assert first['issues']==second['issues']
        expected = json.loads((FIXTURES/'expected_locations.json').read_text())['expected']
        expected_count = sum(len(lines) for rules in expected.values() for lines in rules.values())
        assert len(first['issues'])==expected_count==38
        for issue in first['issues']:
            location = issue['locations'][0]
            rule = issue['evidence'][0]['raw_ref']
            assert location['line'] in {line for lines in expected[location['path']].values() for line in lines}
            assert any(e['tool']=='view_file' for e in issue['evidence'])
            assert not location['stale'] and len(location['snippet_hash'])==64
            assert issue['needs_human_review']
        file = root/'vulnerable.py'
        file.write_text(file.read_text()+'\n# changed after audit\n')
        status = await registry.call('get_audit_status',{'audit_id':first['audit_id'],'limit':200},'test')
        affected = [loc for i in status['data']['issues'] for loc in i['locations'] if loc['path']=='vulnerable.py']
        assert affected and all(loc['stale'] for loc in affected)
    finally:
        await registry.close()


@pytest.mark.anyio
async def test_clean_controls_and_no_ignore_suppression(tmp_path):
    root = tmp_path/'repo'
    root.mkdir()
    for file in FIXTURES.glob('clean.*'):
        shutil.copyfile(file,root/file.name)
    registry = ToolRegistry(Config(allowed_roots=[root],data_dir=tmp_path/'state',model_tier='rules'))
    try:
        result = await audit(registry,root)
        assert result['issues']==[]
        assert result['coverage']['files']==11
        shutil.copyfile(FIXTURES/'vulnerable.py',root/'vulnerable.py')
        (root/'.gitignore').write_text('vulnerable.py\n')
        (root/'binary.png').write_bytes(b'\x89PNG\x00\x00')
        result = await audit(registry,root)
        assert len(result['issues'])==4
        assert result['coverage']['excluded_files']==1
        assert any('binary' in w for w in result['warnings'])
    finally:
        await registry.close()


@pytest.mark.anyio
async def test_status_pagination_and_review_isolation(tmp_path):
    root = tmp_path/'repo'
    root.mkdir()
    shutil.copyfile(FIXTURES/'vulnerable.py',root/'vulnerable.py')
    registry = ToolRegistry(Config(allowed_roots=[root],data_dir=tmp_path/'state',model_tier='rules'))
    try:
        report = await audit(registry,root)
        identifier = report['audit_id']
        page = await registry.call('get_audit_status',{'audit_id':identifier,'limit':1},'test')
        assert page['data']['total_issues']==4 and page['data']['next_offset']==1 and page['data']['truncated']
        denied = await registry.call('get_audit_status',{'audit_id':identifier},'other')
        assert denied['isError']
        issue_id = report['issues'][0]['id']
        registry.store.review(identifier,'test',issue_id,'confirmed')
        assert registry.store.get(identifier,'test')['issues'][0]['review']=='confirmed'
    finally:
        await registry.close()
