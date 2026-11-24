"""Clean dataset v3 metadata and freeze LocalGuard gold_v1."""
from __future__ import annotations

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from build_training_dataset_v1 import load, write
from merge_remaining_v3 import group_key, sft_messages

DATA = ROOT / '.workbuddy' / 'training_data'
V3 = DATA / 'dataset_v3'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_bytes(repo: Path, commit: str, path: str) -> bytes:
    return subprocess.check_output(['git', '-C', str(repo), 'show', f'{commit}:{path}'], stderr=subprocess.PIPE)


def pinned_bytes(record: dict) -> bytes:
    prov = record['provenance']
    finding = record['finding']
    path = finding['path']
    commit = prov.get('code_commit') or prov.get('upstream_revision') or prov.get('resolved_fix_commit')
    if not commit:
        raise ValueError(f'Missing pinned commit for {record["id"]}')
    if prov.get('cve') and prov.get('source_path'):
        return Path(prov['source_path']).read_bytes()
    repo_url = prov.get('repo_url', '')
    if 'StarryFirefly-Armillary/localguard' in repo_url:
        return git_bytes(ROOT, commit, path)
    if 'StarryFirefly-s-Blog-personal' in repo_url:
        return git_bytes(ROOT / 'repos' / 'StarryFirefly-s-Blog-personal', commit, path)
    target = prov.get('target')
    if target:
        target = Path(target)
        root = Path(subprocess.check_output(
            ['git', '-C', str(target), 'rev-parse', '--show-toplevel'], text=True, encoding='utf-8'
        ).strip())
        relative = (target / path).resolve().relative_to(root.resolve()).as_posix()
        return git_bytes(root, commit, relative)
    raise ValueError(f'Cannot resolve pinned source for {record["id"]}')


def clean_record(record: dict) -> dict:
    record = copy.deepcopy(record)
    record['gold_status'] = 'frozen'
    if record['sample_kind'] != 'triage_finding':
        return record
    prov = record['provenance']
    materialized = prov.pop('file_sha256', None)
    if not materialized:
        raise ValueError(f'Missing materialized source hash for {record["id"]}')
    prov['materialized_source_sha256'] = materialized
    prov['pinned_file_sha256'] = sha(pinned_bytes(record))
    if record.get('label_origin') == 'human_confirmed_revalidated':
        record['quality_flags'] = [flag for flag in record.get('quality_flags', []) if flag != 'missing_embedded_source']
        record['training_action'] = 'keep'
        record['original_label_origin'] = 'human_confirmed'
        record['revalidated_by'] = 'AI'
        record['revalidation_method'] = 'pinned_source_static_review'
    return record


def file_manifest(path: Path) -> dict:
    return {'path': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', type=Path, default=DATA / 'gold_v1')
    args = parser.parse_args()
    records = [clean_record(record) for record in load(V3 / 'records.jsonl')]
    train_ids = {record['id'] for record in load(V3 / 'train.jsonl')}
    eval_ids = {record['id'] for record in load(V3 / 'eval.jsonl')}
    train = [record for record in records if record['id'] in train_ids]
    evaluation = [record for record in records if record['id'] in eval_ids]
    if len(train) + len(evaluation) != len(records):
        raise ValueError('Train/eval split lost records')
    if {group_key(r) for r in train} & {group_key(r) for r in evaluation}:
        raise ValueError('Group leakage in gold_v1')
    write(args.out_dir / 'records.jsonl', records)
    write(args.out_dir / 'train.jsonl', train)
    write(args.out_dir / 'eval.jsonl', evaluation)
    write(args.out_dir / 'sft_train.jsonl', [{**r, 'messages': sft_messages(r)} for r in train])
    write(args.out_dir / 'sft_eval.jsonl', [{**r, 'messages': sft_messages(r)} for r in evaluation])
    merged = load(V3 / 'merged_records.jsonl')
    write(args.out_dir / 'merged_records.jsonl', merged)
    write(args.out_dir / 'rejected_records.jsonl', [])
    write(args.out_dir / 'unreviewed_records.jsonl', [])
    frozen_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
    manifest = {
        'kind': 'localguard_gold_v1',
        'frozen': True,
        'frozen_at': frozen_at,
        'source_dataset': str(V3 / 'records.jsonl'),
        'total_records': len(records),
        'labels': dict(Counter(r['label'] for r in records)),
        'sample_kinds': dict(Counter(r['sample_kind'] for r in records)),
        'label_origin': dict(Counter(r['label_origin'] for r in records)),
        'needs_user_confirmation': sum(r['needs_user_confirmation'] for r in records),
        'triage_records': sum(r['sample_kind'] == 'triage_finding' for r in records),
        'triage_with_source': sum(bool(r.get('finding', {}).get('source')) for r in records if r['sample_kind'] == 'triage_finding'),
        'triage_with_pinned_hash': sum(bool(r['provenance'].get('pinned_file_sha256')) for r in records if r['sample_kind'] == 'triage_finding'),
        'stale_missing_source_flags': sum('missing_embedded_source' in r.get('quality_flags', []) for r in records),
        'stale_training_actions': sum(r.get('training_action') == 'keep_after_source_materialization' for r in records),
        'merged_duplicates': len(merged),
        'split_counts': {'train': len(train), 'eval': len(evaluation)},
        'split_labels': {
            'train': dict(Counter(r['label'] for r in train)),
            'eval': dict(Counter(r['label'] for r in evaluation)),
        },
        'group_leakage': 0,
        'files': [],
        'notes': [
            'Labels and train/eval split are unchanged from reviewed dataset v3.',
            'materialized_source_sha256 records source bytes used for context; pinned_file_sha256 records the fixed Git blob bytes.',
            'Original human confirmation and later AI revalidation are recorded separately.',
        ],
    }
    for name in ('records.jsonl', 'train.jsonl', 'eval.jsonl', 'sft_train.jsonl', 'sft_eval.jsonl', 'merged_records.jsonl'):
        manifest['files'].append(file_manifest(args.out_dir / name))
    (args.out_dir / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
