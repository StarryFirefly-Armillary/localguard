import asyncio
import json
from pathlib import Path
import uuid

from localguard.config import Config
from localguard.registry import ToolRegistry
from localguard.reporting import from_finding


async def main():
    root = Path(__file__).resolve().parents[1]
    source = root/'.localguard/offline-validation/state/evidence/447b254c199640c39b985c24afdd43f0/grype.json'
    trace = json.loads(source.read_text('utf-8'))
    target = root/'fixtures'
    registry = ToolRegistry(Config(allowed_roots=[target], data_dir=root/'.localguard/report-regression-state', model_tier='rules'))
    session = uuid.uuid4().hex
    queued = registry.store.enqueue(session, {'target':str(target)})
    snapshot = {}
    candidates = []
    try:
        for finding in trace['findings']:
            path = target/finding['path']
            line = finding['line']
            read = await registry.call('view_file', {'path':str(path),'start_line':line,'end_line':line}, session, 'captured-evidence-replay')
            assert not read['isError'], read
            snapshot[finding['path']] = read['data']['hash']
            candidates.append(from_finding(finding, read['data']['lines'][0]['text']))
        result = {**queued, 'status':'completed', 'progress':100, 'issues':candidates, 'root':str(target)}
        await registry.publish_report(queued['audit_id'], result, session, target, snapshot)
        stored = registry.store.get(queued['audit_id'], session)
        assert len(stored['issues']) == len(trace['findings']) == 11
        assert len({issue['id'] for issue in stored['issues']}) == 11
        request_issues = [issue for issue in stored['issues'] if 'requests' in issue['title']]
        assert len(request_issues) == 5
        assert any('2.33.0' in issue['remediation'] for issue in request_issues)
        report = {'captured_scanner_evidence':str(source),'audit_id':queued['audit_id'],
                  'original_advisories':len(trace['findings']),'retained_issues':len(stored['issues']),
                  'requests_advisories':len(request_issues),'newest_requests_fix_preserved':True,
                  'source':'Replay of actual recorded Grype output through current view_file and publication gate',
                  'fresh_external_scanner_run':False}
        (root/'.localguard/report-regression.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report,indent=2))
    finally:
        await registry.close()


if __name__ == '__main__':
    asyncio.run(main())
