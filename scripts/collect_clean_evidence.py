"""Collect genuine clean-code training evidence (no fabricated negatives).

For each genuinely clean file (real fixtures + TRAIN-split safe implementations):
  1. call view_file through the shared ToolRegistry -> genuine tool_evidence log
  2. run the deterministic `patterns` scanner over the containing allowed root
     -> a genuinely zero-finding result, saved as a raw artifact with its sha256
  3. verify a clean_evidence record with the strict localguard.training validator

Hard negatives come only from train-split safe implementations; no heldout CVE
or file is used, so the held-out evaluation stays untouched. All three mandatory
sources remain required at load time. Nothing is downloaded and no file is run.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import json
from pathlib import Path
import uuid

from localguard.config import Config
from localguard.registry import ToolRegistry
from localguard.training import validate_record

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'fixtures' / 'clean'
CURATION = ROOT / '.localguard' / 'curation'
# Machine-specific data paths come from the environment; defaults are relative.
_DATA_ROOT = Path(os.environ.get('LG_TRAIN_DATA_DIR', 'data'))
HELDOUT = _DATA_ROOT / 'heldout.jsonl'
TRAIN = _DATA_ROOT / 'train.jsonl'


def rows(path):
    return [json.loads(l) for l in path.read_text('utf-8').splitlines() if l.strip()]


async def collect():
    state = CURATION / 'clean-evidence'
    state.mkdir(parents=True, exist_ok=True)
    artifacts = state / 'artifacts'
    artifacts.mkdir(parents=True, exist_ok=True)
    hard_dir = state / 'train-safe'
    hard_dir.mkdir(parents=True, exist_ok=True)

    def cve_of(row):
        return row.get('cve') or row.get('provenance', {}).get('cve')

    heldout_cves = {cve_of(r) for r in rows(HELDOUT)}
    # Write train-split safe implementations as inert text (never executed).
    targets = []
    for row in rows(TRAIN):
        if row['source'] == 'security_dialogue' and cve_of(row) not in heldout_cves:
            target = hard_dir / (row['id'] + '.txt')
            target.write_text(row['safe_implementation'], encoding='utf-8')
            targets.append(target)

    roots = [str(FIXTURES.resolve()), str(hard_dir.resolve())]
    config = Config(allowed_roots=roots, data_dir=str(state / 'state'),
                    model_tier='rules', offline=True)
    registry = ToolRegistry(config)
    records = []
    try:
        # Scan each root once; only keep if genuinely zero findings.
        scan_by_root = {}
        for root in roots:
            call = await registry.call('run_scanner',
                {'scanner': 'patterns', 'target': root, 'ruleset': 'security'},
                'clean-evidence-scan', 'clean-evidence')
            if call['isError']:
                raise RuntimeError(call['error'])
            scan = call['data']
            raw = json.dumps(scan, ensure_ascii=False).encode('utf-8')
            artifact = artifacts / (Path(root).name + '-scan.json')
            artifact.write_bytes(raw)
            scan_by_root[root] = (scan, artifact, hashlib.sha256(raw).hexdigest())

        for source in sorted(FIXTURES.glob('clean.*')) + sorted(targets):
            root = str(source.parent.resolve())
            scan, artifact, digest = scan_by_root[root]
            if scan['status'] != 'completed' or scan['findings']:
                raise RuntimeError(f'{source.name}: owning root did not scan clean')
            session = uuid.uuid4().hex
            args = {'path': str(source.resolve()), 'start_line': 1, 'end_line': 4}
            read = await registry.call('view_file', args, session, 'clean-evidence')
            if read['isError']:
                raise RuntimeError(read['error'])

            with registry.store.connect() as db:
                read_id = db.execute(
                    "SELECT id FROM logs WHERE json_extract(payload,'$.event')='tool_evidence' "
                    "AND json_extract(payload,'$.session_hash')=? ORDER BY id DESC LIMIT 1",
                    (hashlib.sha256(session.encode()).hexdigest(),),
                ).fetchone()[0]

            record = {
                'id': 'clean-' + source.name,
                'source': 'clean_evidence',
                'root': root,
                'call': {'name': 'view_file', 'arguments': args},
                'result': read['data'],
                'issues': [],
                'explanation': 'Deterministic patterns scan returned zero findings for this clean file.',
                'provenance': {
                    'database': str(registry.store.path),
                    'call_log_id': read_id,
                    'scan_log_id': 0,  # replaced below: need this session's scan log
                    'scan_artifact': str(artifact.resolve()),
                    'scan_sha256': digest,
                    'session': session,
                },
            }
            # The scan for the root used a different session; validator requires
            # scan_log.session == record.session, so re-scan inside this session.
            call = await registry.call('run_scanner',
                {'scanner': 'patterns', 'target': root, 'ruleset': 'security'},
                session, 'clean-evidence')
            if call['isError'] or call['data']['status'] != 'completed' or call['data']['findings']:
                raise RuntimeError(f'{source.name}: per-session scan did not confirm clean')
            with registry.store.connect() as db:
                scan_id = db.execute(
                    "SELECT id FROM logs WHERE json_extract(payload,'$.event')='tool_call' "
                    "AND json_extract(payload,'$.tool_name')='run_scanner' "
                    "AND json_extract(payload,'$.session')=? ORDER BY id DESC LIMIT 1",
                    (session,),
                ).fetchone()[0]
            record['provenance']['scan_log_id'] = scan_id
            record['provenance']['scan_sha256'] = hashlib.sha256(
                json.dumps(call['data'], ensure_ascii=False).encode('utf-8')).hexdigest()
            artifact.write_bytes(json.dumps(call['data'], ensure_ascii=False).encode('utf-8'))
            validate_record(record)
            records.append(record)
            print(f'validated {record["id"]}: scan_log={scan_id} findings=0')

        out = CURATION / 'clean_evidence.jsonl'
        out.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records), encoding='utf-8')
        print(json.dumps({'records': len(records), 'output': str(out)}, ensure_ascii=False))
    finally:
        await registry.close()


if __name__ == '__main__':
    asyncio.run(collect())
