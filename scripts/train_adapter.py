"""Explicit, offline-only CLI. --help/validate/evaluate never load model weights.

Examples (absolute local paths required):
  python scripts/train_adapter.py validate --data C:/data/curated.jsonl
  python scripts/train_adapter.py train --data C:/data/curated.jsonl \
      --base-model C:/models/Qwen3.5-4B --output C:/models/adapter --rank 16
  python scripts/train_adapter.py evaluate --before C:/eval/before.json \
      --after C:/eval/after.json

Evaluation files are arrays of measured held-out predictions (see evaluate() in
localguard.training). The CLI never manufactures predictions. Merging is gated
by the same paired metrics and requires enough CPU RAM for unquantized weights.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys

# Direct script execution works without installing the package or changing cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from localguard.training import (  # noqa: E402
    DatasetError, compare_evaluations, ingest_logs, load_dataset,
    merge_adapter, train_adapter,
)


def _predictions(path):
    if not path.is_absolute() or not path.is_file() or path.stat().st_size > 20_000_000:
        raise DatasetError('Evaluation input must be a bounded absolute local JSON file')
    data = json.loads(path.read_text('utf-8'))
    if not isinstance(data, list):
        raise DatasetError('Evaluation input must be an array of measured predictions')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description='Validate local provenance, train offline NF4 QLoRA, and gate measured adapter improvements.')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('validate', 'train'):
        command = commands.add_parser(name)
        command.add_argument('--data', type=Path, nargs='+', required=True, help='Local JSONL files; all three labelled sources required')
        command.add_argument('--logs', type=Path, help='Optional read-only SQLite log ingestion; negatives never become SFT targets')
        if name == 'train':
            command.add_argument('--base-model', type=Path, required=True, help='Existing local HF model directory, never a hub id')
            command.add_argument('--output', type=Path, required=True)
            command.add_argument('--rank', type=int, choices=(16, 32), default=16)
            command.add_argument('--gradient-accumulation', type=int, default=8)
            command.add_argument('--epochs', type=float, default=1.0)
            command.add_argument('--no-gradient-checkpointing', action='store_true',
                                 help='Disable activation checkpointing (faster when attention kernels fall back to PyTorch; requires confirmed 8GB headroom at batch 1)')
            command.add_argument('--max-length', type=int, default=4096,
                                 help='Training window; values below 4096 truncate the oldest evidence tokens but never the supervised answer')
            command.add_argument('--max-negative-ratio', type=float,
                                 help='Cap negative (clean_evidence) turns relative to positive turns, e.g. 1.0 for balance')
            command.add_argument('--skip-oversized', action='store_true',
                                 help='Skip turns whose supervised answer will not fit --max-length instead of failing (recorded in training manifest)')
            command.add_argument('--resource-dir', type=Path, default=Path.home()/'.localguard', help='Shared LocalGuard state directory for exclusive host resource scheduling')
    for name in ('evaluate', 'merge'):
        command = commands.add_parser(name)
        command.add_argument('--before', type=Path, required=True)
        command.add_argument('--after', type=Path, required=True)
        command.add_argument('--min-fpr-improvement', type=float, default=0.001, help='Minimum absolute FPR reduction, strictly positive')
        if name == 'merge':
            command.add_argument('--base-model', type=Path, required=True)
            command.add_argument('--adapter', type=Path, required=True)
            command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ('evaluate', 'merge'):
            result = compare_evaluations(_predictions(args.before), _predictions(args.after), args.min_fpr_improvement)
            if args.command == 'merge' and result['passed']:
                result['merge'] = merge_adapter(args.base_model, args.adapter, args.output)
            print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
            return 0 if result['passed'] else 2
        records = load_dataset(args.data)
        result = {'validated_records': len(records), 'sources': {source: sum(r['source'] == source for r in records) for source in ('cve_patch', 'security_dialogue', 'tool_call')},
                  'provenance': 'Verified against local artifacts only; upstream authenticity was not independently checked.'}
        if args.logs:
            logs = ingest_logs(args.logs)
            result['logs'] = {key: len(value) for key, value in logs.items()}
            result['logs']['note'] = 'Separate hashed negatives and metadata; no automatic positive training targets.'
        if args.command == 'train':
            from localguard.storage import Store
            if not args.resource_dir.is_absolute() or not args.resource_dir.is_dir():
                raise DatasetError('resource-dir must be an existing absolute LocalGuard state directory')
            async def scheduled_training():
                async with Store(args.resource_dir).resource():
                    return train_adapter(args.base_model, records, args.output, rank=args.rank,
                                         accumulation=args.gradient_accumulation, epochs=args.epochs,
                                         gradient_checkpointing=not args.no_gradient_checkpointing,
                                         max_length=args.max_length, skip_oversized=args.skip_oversized,
                                         max_negative_ratio=args.max_negative_ratio)
            result['training'] = asyncio.run(scheduled_training())
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except (DatasetError, OSError, ValueError) as exc:
        print(f'Not completed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
