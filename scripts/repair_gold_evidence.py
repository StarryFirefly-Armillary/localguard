"""Repair non-Python evidence truncation and re-freeze gold_v1."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from build_training_dataset_v1 import load, write
from evidence_context import build_evidence
from freeze_gold_v1 import pinned_bytes, sha
from merge_remaining_v3 import LANGUAGES, group_key, sft_messages

DATA = ROOT / '.workbuddy' / 'training_data'
GOLD = DATA / 'gold_v1'


def repair_record(record: dict) -> tuple[dict, bool]:
    if record['sample_kind'] != 'triage_finding':
        record['gold_status'] = 'frozen'
        return record, False
    finding = record['finding']
    suffix = Path(finding['path']).suffix.lower()
    if suffix in {'.py', '.pyw', '.pyi'}:
        record['gold_status'] = 'frozen'
        return record, False
    raw = pinned_bytes(record)
    text = raw.decode('utf-8-sig', errors='replace')
    language = LANGUAGES.get(suffix, 'unknown')
    line = int(finding['line'])
    lines = text.splitlines()
    start, end = max(1, line - 3), min(len(lines), line + 3)
    finding['source_window'] = [{'line': n, 'text': lines[n - 1]} for n in range(start, end + 1)]
    finding['source'] = [item for item in build_evidence(text, line, language, max_chars=1200) if item['text'].strip()]
    finding['language'] = language
    finding['source_basis'] = 'pinned_git_blob'
    record['provenance']['materialized_source_sha256'] = sha(raw)
    record['provenance']['pinned_file_sha256'] = sha(raw)
    record['evidence_repair'] = 'non_python_inline_content_preserved'
    record['gold_status'] = 'frozen'
    return record, True


def file_manifest(path: Path) -> dict:
    return {'path': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gold-dir', type=Path, default=GOLD)
    args = parser.parse_args()
    old_manifest = json.loads((args.gold_dir / 'manifest.json').read_text(encoding='utf-8'))
    backup = args.gold_dir.with_name(args.gold_dir.name + '_pre_evidence_fix')
    if backup.exists():
        raise FileExistsError(f'Backup already exists: {backup}')
    shutil.copytree(args.gold_dir, backup)
    records = load(args.gold_dir / 'records.jsonl')
    repaired = [repair_record(record) for record in records]
    records = [record for record, _ in repaired]
    repaired_count = sum(changed for _, changed in repaired)
    train_ids = {record['id'] for record in load(args.gold_dir / 'train.jsonl')}
    eval_ids = {record['id'] for record in load(args.gold_dir / 'eval.jsonl')}
    train = [record for record in records if record['id'] in train_ids]
    evaluation = [record for record in records if record['id'] in eval_ids]
    if {group_key(r) for r in train} & {group_key(r) for r in evaluation}:
        raise ValueError('Group leakage after evidence repair')
    write(args.gold_dir / 'records.jsonl', records)
    write(args.gold_dir / 'train.jsonl', train)
    write(args.gold_dir / 'eval.jsonl', evaluation)
    write(args.gold_dir / 'sft_train.jsonl', [{**r, 'messages': sft_messages(r)} for r in train])
    write(args.gold_dir / 'sft_eval.jsonl', [{**r, 'messages': sft_messages(r)} for r in evaluation])
    manifest = {
        'kind': 'localguard_gold_v1',
        'frozen': True,
        'frozen_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'supersedes_manifest_sha256': sha((backup / 'manifest.json').read_bytes()),
        'backup_directory': str(backup),
        'repair': {
            'non_python_records_rebuilt': repaired_count,
            'reason': 'Preserve inline #, //, URLs, Base64, Markdown anchors, and Ruby interpolation.',
            'cve_pairs_gold_status_added': sum(r['sample_kind'] == 'cve_function_pair' for r in records),
        },
        'total_records': len(records),
        'labels': dict(Counter(r['label'] for r in records)),
        'sample_kinds': dict(Counter(r['sample_kind'] for r in records)),
        'label_origin': dict(Counter(r['label_origin'] for r in records)),
        'needs_user_confirmation': sum(r['needs_user_confirmation'] for r in records),
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
            'Labels and train/eval split are unchanged.',
            'Non-Python evidence is rebuilt from pinned Git blobs with inline content preserved.',
            '108 AI-reviewed records remain needs_user_confirmation=true.',
        ],
    }
    for name in ('records.jsonl', 'train.jsonl', 'eval.jsonl', 'sft_train.jsonl', 'sft_eval.jsonl', 'merged_records.jsonl'):
        manifest['files'].append(file_manifest(args.gold_dir / name))
    (args.gold_dir / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
