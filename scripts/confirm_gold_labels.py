"""Apply explicit user confirmation to all pending gold_v1 labels."""
from __future__ import annotations

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from build_training_dataset_v1 import load, write
from merge_remaining_v3 import group_key, sft_messages

DATA = ROOT / '.workbuddy' / 'training_data'
GOLD = DATA / 'gold_v1'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def confirm_record(record: dict, confirmed_at: str) -> dict:
    record = copy.deepcopy(record)
    was_pending = bool(record.get('needs_user_confirmation'))
    if was_pending:
        record['original_label_origin'] = record.get('label_origin')
        record['previous_annotator'] = record.get('annotator')
        record['label_origin'] = 'human_confirmed'
        record['confirmation_method'] = 'user_bulk_confirmation'
    else:
        record.setdefault('original_label_origin', 'human_confirmed')
        record.setdefault('confirmation_method', 'prior_human_confirmation')
    record['annotator'] = 'user'
    record['human_label'] = record['label']
    record['confirmed_by'] = 'user'
    record['confirmed_at'] = confirmed_at
    record['needs_user_confirmation'] = False
    record['gold_status'] = 'frozen'
    return record


def file_manifest(path: Path) -> dict:
    return {'path': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gold-dir', type=Path, default=GOLD)
    args = parser.parse_args()
    backup = args.gold_dir.with_name(args.gold_dir.name + '_pre_user_confirmation')
    if backup.exists():
        raise FileExistsError(f'Backup already exists: {backup}')
    shutil.copytree(args.gold_dir, backup)
    confirmed_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
    records = [confirm_record(record, confirmed_at) for record in load(args.gold_dir / 'records.jsonl')]
    train_ids = {record['id'] for record in load(args.gold_dir / 'train.jsonl')}
    eval_ids = {record['id'] for record in load(args.gold_dir / 'eval.jsonl')}
    train = [record for record in records if record['id'] in train_ids]
    evaluation = [record for record in records if record['id'] in eval_ids]
    if {group_key(r) for r in train} & {group_key(r) for r in evaluation}:
        raise ValueError('Group leakage after label confirmation')
    write(args.gold_dir / 'records.jsonl', records)
    write(args.gold_dir / 'train.jsonl', train)
    write(args.gold_dir / 'eval.jsonl', evaluation)
    write(args.gold_dir / 'sft_train.jsonl', [{**r, 'messages': sft_messages(r)} for r in train])
    write(args.gold_dir / 'sft_eval.jsonl', [{**r, 'messages': sft_messages(r)} for r in evaluation])
    manifest = {
        'kind': 'localguard_gold_v1',
        'frozen': True,
        'frozen_at': confirmed_at,
        'supersedes_manifest_sha256': sha((backup / 'manifest.json').read_bytes()),
        'backup_directory': str(backup),
        'confirmation': {
            'confirmed_by': 'user',
            'confirmed_at': confirmed_at,
            'newly_confirmed_records': sum(r['label_origin'] == 'human_confirmed' for r in records),
            'previously_confirmed_records': sum(r['label_origin'] == 'human_confirmed_revalidated' for r in records),
            'needs_user_confirmation': 0,
        },
        'total_records': len(records),
        'labels': dict(Counter(r['label'] for r in records)),
        'sample_kinds': dict(Counter(r['sample_kind'] for r in records)),
        'label_origin': dict(Counter(r['label_origin'] for r in records)),
        'needs_user_confirmation': sum(r['needs_user_confirmation'] for r in records),
        'human_label_present': sum('human_label' in r for r in records),
        'triage_records': sum(r['sample_kind'] == 'triage_finding' for r in records),
        'triage_with_source': sum(bool(r.get('finding', {}).get('source')) for r in records if r['sample_kind'] == 'triage_finding'),
        'triage_with_pinned_hash': sum(bool(r['provenance'].get('pinned_file_sha256')) for r in records if r['sample_kind'] == 'triage_finding'),
        'gold_status_counts': dict(Counter(r.get('gold_status') for r in records)),
        'split_counts': {'train': len(train), 'eval': len(evaluation)},
        'split_labels': {
            'train': dict(Counter(r['label'] for r in train)),
            'eval': dict(Counter(r['label'] for r in evaluation)),
        },
        'group_leakage': 0,
        'files': [],
        'notes': [
            'All 132 labels are now explicitly user-confirmed.',
            'Original AI/dataset review provenance is preserved in original_label_origin and previous_annotator.',
            'Labels, reasons, evidence, and train/eval membership are unchanged.',
        ],
    }
    for name in ('records.jsonl', 'train.jsonl', 'eval.jsonl', 'sft_train.jsonl', 'sft_eval.jsonl', 'merged_records.jsonl'):
        manifest['files'].append(file_manifest(args.gold_dir / name))
    (args.gold_dir / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
