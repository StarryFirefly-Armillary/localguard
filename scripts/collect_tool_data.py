from __future__ import annotations

import argparse
import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import uuid

from localguard.config import Config
from localguard.registry import ToolRegistry
from localguard.reporting import EvidenceError, from_finding
from localguard.training import ingest_logs, validate_record


def changed_old_line(diff, target, start, end):
    old = None
    active = in_hunk = False
    insertions = []
    for line in diff.split('\n'):
        if line.startswith('diff --git '):
            active = in_hunk = False
            old = None
        elif not in_hunk and line.startswith('--- a/'):
            active = line[6:] == target
        elif active:
            match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
            if match:
                in_hunk = True
                old = int(match[1])
                if match[2] == '0' and start <= old + 1 <= end:
                    insertions.append(old + 1)
            elif in_hunk and old is not None and line.startswith('-'):
                if start <= old <= end and line[1:].strip():
                    return old, 'removed_pre_fix_statement'
                old += 1
            elif in_hunk and old is not None and line.startswith(' '):
                old += 1
    if insertions:
        return insertions[0], 'existing_statement_after_inserted_guard'
    raise ValueError('No fix hunk lies inside the verified vulnerable function')


async def collect(directory):
    directory = directory.resolve(strict=True)
    index = json.loads((directory/'source_index.json').read_text('utf-8'))
    dialogues = {record['provenance']['cve']:record for record in
                 map(json.loads,(directory/'security_dialogue.jsonl').read_text('utf-8').splitlines())}
    registry = ToolRegistry(Config(allowed_roots=[directory],data_dir=directory/'traces',model_tier='rules'))
    records=[]
    try:
        for source in index:
            session=uuid.uuid4().hex
            before=source['snapshots']['before']
            file=Path(before['file'])
            root=file
            for _ in Path(source['path']).parts:
                root=root.parent
            span=before['function_span']
            ast=await registry.call('get_ast',{'path':str(file)},session,'training-curation')
            if ast['isError']:
                raise ValueError(ast['error'])
            if not any(node['start_line']==span['start_line'] and node['end_line']==span['end_line'] and
                       ('function' in node['type'] or 'method' in node['type']) for node in ast['data']['nodes']):
                raise ValueError('Pinned vulnerable function was not corroborated by get_ast')
            diff=await registry.call('git_diff',{'repo':source['repository'],'base':source['parent'],'head':source['commit']},session,'training-curation')
            if diff['isError'] or diff['data']['truncated']:
                raise ValueError('Complete deterministic diff unavailable: '+str(diff.get('error','truncated')))
            line, location_basis=changed_old_line(diff['data']['diff'],source['path'],span['start_line'],span['end_line'])
            arguments={'path':str(file),'start_line':max(1,line-2),'end_line':line+2}
            read=await registry.call('view_file',arguments,session,'training-curation')
            if read['isError']:
                raise ValueError(read['error'])
            text=next(row['text'] for row in read['data']['lines'] if row['line']==line)
            dialogue=dialogues[source['cve']]
            advisory=json.loads(Path(dialogue['provenance']['artifact']).read_text('utf-8'))
            severity={'moderate':'medium'}.get(advisory['severity'],advisory['severity'])
            category={'CWE-327':'misconfig','CWE-1321':'injection','CWE-78':'injection','CWE-79':'injection','CWE-89':'injection'}.get(dialogue['cwe'],'other')
            finding={'path':source['path'],'line':line,'title':source['cve']+' documented pre-fix code',
                     'severity':severity,'category':category,'cwe':dialogue['cwe'],'confidence':0.95,
                     'tool':'git_diff','rule_id':source['cve'],'raw_ref':source['commit']+':'+source['path'],
                     'explanation':'The pinned upstream advisory links this historical version and function to '+source['cve']+'. The changed statement is derived from the fix diff; applicability still requires human review.',
                     'remediation':dialogue['remediation']}
            issue=from_finding(finding,text)
            issue['evidence'].append({'tool':'get_ast','raw_ref':before['git_blob']})
            report=registry.rank_and_report([issue],session,root)
            with registry.store.connect() as db:
                call_id=db.execute("SELECT id FROM logs WHERE json_extract(payload,'$.event')='tool_evidence' AND json_extract(payload,'$.session_hash')=? ORDER BY id DESC LIMIT 1",(hashlib.sha256(session.encode()).hexdigest(),)).fetchone()[0]
                validations=[row[0] for row in db.execute("SELECT id FROM logs WHERE json_extract(payload,'$.event')='location_validated' AND json_extract(payload,'$.session')=?",(session,))]
            record={'id':'tool-'+source['cve'],'source':'tool_call','cve':source['cve'],
                    'upstream_revision':source['parent'],'location_basis':location_basis,'root':str(root),'call':{'name':'view_file','arguments':arguments},
                    'result':read['data'],'issues':report['issues'],
                    'provenance':{'database':str(registry.store.path),'call_log_id':call_id,'validation_log_ids':validations,'session':session}}
            validate_record(record)
            records.append(record)
            negative=deepcopy(issue)
            negative['locations'][0]['line']=read['data']['end_line']+1
            try:
                registry.validator.validate(negative,session,root)
            except EvidenceError:
                pass
            else:
                raise AssertionError('Invalid location unexpectedly passed the gate')
        (directory/'tool_call.jsonl').write_text(''.join(json.dumps(record,ensure_ascii=False)+'\n' for record in records),encoding='utf-8')
        negatives=ingest_logs(registry.store.path)
        (directory/'negative_samples.json').write_text(json.dumps(negatives,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'tool_records':len(records),'source':'pinned upstream pre-fix Git snapshots',
                          'fixture_records':0,'database':str(registry.store.path),'negative_groups':{k:len(v) for k,v in negatives.items()}},ensure_ascii=True,indent=2))
    finally:
        await registry.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--curation',type=Path,default=Path('.localguard/curation'))
    asyncio.run(collect(parser.parse_args().curation))
