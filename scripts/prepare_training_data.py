from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from localguard.training import load_dataset, prepare_training_examples

HELDOUT = {'CVE-2020-7598', 'CVE-2021-44906', 'CVE-2022-27776'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--curation', type=Path, default=Path('.localguard/curation'))
    parser.add_argument('--base-model', type=Path, default=Path(os.environ.get('LOCALGUARD_TRAIN_ROOT', 'C:/LocalGuard/training'))/'base-model')
    parser.add_argument('--output', type=Path, default=Path(os.environ.get('LOCALGUARD_TRAIN_ROOT', 'C:/LocalGuard/training'))/'data')
    args = parser.parse_args()
    sources = [args.curation.resolve() / name for name in ('cve_patch.jsonl', 'security_dialogue.jsonl', 'tool_call.jsonl', 'extended/security_dialogue.jsonl')]
    records = load_dataset(sources)
    train, heldout = [], []
    for record in records:
        cve = record['provenance'].get('cve') or record.get('cve')
        (heldout if cve in HELDOUT else train).append(record)
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(args.base_model.resolve()), local_files_only=True, trust_remote_code=False)
    _, train_lengths = prepare_training_examples(tokenizer, train)
    _, test_lengths = prepare_training_examples(tokenizer, heldout)
    args.output.mkdir(parents=True, exist_ok=True)
    for name, items in [('train.jsonl', train), ('heldout.jsonl', heldout)]:
        (args.output / name).write_text(''.join(json.dumps(item, ensure_ascii=False) + '\n' for item in items), encoding='utf-8')
    report = {
        'training_records': len(train), 'heldout_records': len(heldout),
        'training_sources': dict(Counter(item['source'] for item in train)),
        'heldout_sources': dict(Counter(item['source'] for item in heldout)),
        'heldout_cves': sorted(HELDOUT),
        'split_policy': 'Both related minimist CVEs and their patch/dialogue/tool counterparts are held out together; the curl dialogue is also held out. No random record split.',
        'max_sequence_length': 4096, 'max_actual_train_tokens': max(item['tokens'] for item in train_lengths),
        'max_actual_heldout_tokens': max(item['tokens'] for item in test_lengths),
        'assistant_only_loss': True, 'enable_thinking': False,
        'train_turns': train_lengths, 'heldout_turns': test_lengths,
        'input_sha256': {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
        'limitations': ['Small historical seed corpus; not statistically representative.',
                        'This is token/provenance/split validation, not model-quality evaluation.',
                        'No false-positive improvement is claimed by this artifact.'],
    }
    (args.output / 'preflight.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key not in ('train_turns', 'heldout_turns', 'input_sha256')}, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
