from copy import deepcopy
import json

import pytest

from localguard.config import Config
from localguard.registry import ToolRegistry
from localguard.reporting import EvidenceError, from_finding, rank


def dependency(advisory, package='requests', fixed='2.33.0'):
    return from_finding({'path':'requirements.txt', 'line':4, 'title':f'{advisory} in {package} 2.19.1',
                         'severity':'high', 'category':'dependency_cve', 'cwe':'', 'confidence':0.95,
                         'tool':'grype', 'rule_id':advisory, 'raw_ref':f'#/matches/{advisory}',
                         'remediation':f'Upgrade {package} to {fixed}'}, 'requests==2.19.1')


def test_distinct_advisories_at_the_same_line_remain_distinct():
    old = dependency('GHSA-x84v-xcm2-53pg', fixed='2.20.0')
    new = dependency('GHSA-gc5v-m9x4-r6x2', fixed='2.33.0')
    report = rank([old, new])
    assert len(report) == 2
    assert {item['id'] for item in report} == {old['id'], new['id']}
    assert any('2.33.0' in item['remediation'] for item in report)


def test_same_advisory_in_different_packages_has_distinct_identity():
    first = dependency('CVE-2026-12345', 'first-package')
    second = dependency('CVE-2026-12345', 'second-package')
    assert first['id'] != second['id']
    assert len(rank([first, second])) == 2


def test_repeated_detection_preserves_each_supported_remediation_without_mutation():
    first = dependency('CVE-2026-12345', fixed='2.20.0')
    second = deepcopy(first)
    second['evidence'] = [{'tool':'pip-audit', 'raw_ref':'#/dependencies/0/vulns/0'}]
    second['remediation'] = 'Upgrade requests to 2.33.0 for this supported branch'
    originals = deepcopy([first, second])
    result = rank([first, second])
    assert len(result) == 1
    assert len(result[0]['evidence']) == 2
    assert '2.20.0' in result[0]['remediation'] and '2.33.0' in result[0]['remediation']
    assert [first, second] == originals


def test_secondary_locations_are_part_of_the_duplicate_identity():
    first = dependency('CVE-2026-12345')
    second = deepcopy(first)
    second['locations'].append({**first['locations'][0], 'path':'another-lockfile.json', 'line':10})
    assert len(rank([first, second])) == 2


@pytest.mark.anyio
async def test_publication_rejects_a_stale_scanner_snapshot_even_after_reread(tmp_path):
    root = tmp_path/'repo'
    root.mkdir()
    source = root/'requirements.txt'
    source.write_text('first\nsecond\nthird\nrequests==2.19.1\n')
    registry = ToolRegistry(Config(allowed_roots=[root], data_dir=tmp_path/'state', model_tier='rules'))
    queued = registry.store.enqueue('s', {'target':str(root)})
    _, _, original_hash = registry.policy.read(str(source))
    issue = dependency('GHSA-x84v-xcm2-53pg')
    source.write_text('changed elsewhere\nsecond\nthird\nrequests==2.19.1\n')
    result = {**queued, 'issues':[issue], 'status':'completed'}
    with pytest.raises(EvidenceError, match='changed after scanning'):
        await registry.publish_report(queued['audit_id'], result, 's', root, {'requirements.txt':original_hash})
    assert registry.store.get(queued['audit_id'], 's')['issues'] == []
    with registry.store.connect() as db:
        logs = [json.loads(row[0]) for row in db.execute('SELECT payload FROM logs')]
    assert any(log.get('event') == 'location_rejected' and log.get('validation') == 'stale' for log in logs)
    await registry.close()


@pytest.mark.anyio
async def test_every_nonempty_pipeline_write_passes_the_shared_gate_again(tmp_path, monkeypatch):
    root = tmp_path/'repo'
    root.mkdir()
    lines = ['value = 0'] * 700
    lines[16] = 'auth_bypass = True'
    lines[649] = 'auth_bypass = True'
    (root/'sample.py').write_text('\n'.join(lines), encoding='utf-8')
    registry = ToolRegistry(Config(allowed_roots=[root], data_dir=tmp_path/'state', model_tier='rules'))
    validated_since_write = set()
    nonempty_writes = []
    actual_gate = registry.rank_and_report
    actual_update = registry.store.update

    def signature(issue):
        return json.dumps(issue, sort_keys=True)

    def gate(issues, session, root):
        result = actual_gate(issues, session, root)
        validated_since_write.update(signature(issue) for issue in result['issues'])
        return result

    def update(audit_id, result):
        if result['issues']:
            assert all(signature(issue) in validated_since_write for issue in result['issues']), 'A nonempty report bypassed the current publication gate'
            nonempty_writes.append(len(result['issues']))
        actual_update(audit_id, result)
        validated_since_write.clear()

    monkeypatch.setattr(registry, 'rank_and_report', gate)
    monkeypatch.setattr(registry.store, 'update', update)
    queued = registry.store.enqueue('s', {'target':str(root), 'scanners':['patterns'], 'include_dependencies':False, 'model_tier':'rules'})
    try:
        await registry.engine.execute(registry.store.claim())
        result = registry.store.get(queued['audit_id'], 's')
        assert result['status'] == 'completed', result
        assert nonempty_writes
        assert {loc['line'] for issue in result['issues'] for loc in issue['locations']} == {17, 650}
    finally:
        await registry.close()
