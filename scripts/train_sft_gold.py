"""Offline SFT entry for gold_v1 messages-format data.

Separate from train_adapter.py on purpose: that path enforces the legacy
cve_patch/security_dialogue/tool_call sources via validate_record() and
CANNOT consume sft_train.jsonl (which carries ready-made chat messages).
This entry reads messages directly; no conversion back to the old format.

Offline-only, explicit opt-in. `validate` never loads model weights.
`train` creates a NEW adapter directory and refuses to overwrite existing ones.

Usage:
  python scripts/train_sft_gold.py validate --data .workbuddy/training_data/gold_v1/sft_train.jsonl \
      --base-model E:/LocalAI/LocalGuard/merged-balanced-1to1 --limit 3
  python scripts/train_sft_gold.py train --data ... --base-model ... --output <NEW_DIR> --epochs 1
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from localguard.training import DatasetError, _absolute  # noqa: E402


def load_sft(path: Path) -> list[dict]:
    rows = []
    with path.open('rb') as fh:
        for raw in fh:
            if not raw.strip():
                continue
            row = json.loads(raw)
            msgs = row.get('messages')
            if not isinstance(msgs, list) or len(msgs) < 2:
                raise DatasetError(f'{row.get("id")}: missing chat messages')
            roles = [m.get('role') for m in msgs]
            if roles[0] != 'system' or roles[-1] != 'assistant':
                raise DatasetError(f'{row.get("id")}: expected system...assistant messages')
            rows.append(row)
    return rows


def _supervised_turns(tokenizer, row: dict, max_length: int) -> list[dict]:
    """Tokenize with safe assistant-only loss mask (mirrors training.py)."""
    msgs = row['messages']
    out = []
    for index, message in enumerate(msgs):
        if message.get('role') != 'assistant':
            continue
        options = {'tokenize': False, 'enable_thinking': False}
        prefix = tokenizer.apply_chat_template(msgs[:index], add_generation_prompt=True, **options)
        full = tokenizer.apply_chat_template(msgs[:index + 1], add_generation_prompt=False, **options)
        if not full.startswith(prefix):
            raise DatasetError(f'{row.get("id")}: chat template lacks safe assistant-only masking')
        ids = tokenizer(full, add_special_tokens=False)['input_ids']
        prefix_ids = tokenizer(prefix, add_special_tokens=False)['input_ids']
        if ids[:len(prefix_ids)] != prefix_ids or len(ids) <= len(prefix_ids):
            raise DatasetError(f'{row.get("id")}: token boundaries break answer masking')
        answer_len = len(ids) - len(prefix_ids)
        if len(ids) > max_length:
            keep = max_length - answer_len
            if keep < 64:
                raise DatasetError(f'{row.get("id")}: supervised answer exceeds seq{max_length}')
            ids, prefix_ids = ids[-max_length:], prefix_ids[-keep:]
            if len(ids) - len(prefix_ids) != answer_len:
                raise DatasetError(f'{row.get("id")}: truncation broke answer alignment')
        out.append({
            'input_ids': ids, 'attention_mask': [1] * len(ids),
            'labels': [-100] * len(prefix_ids) + ids[len(prefix_ids):],
            'id': row.get('id'), 'tokens': len(ids), 'supervised_tokens': answer_len,
        })
    return out


def _base_tokenizer(base_model: Path):
    from transformers import AutoTokenizer
    return AutoTokenizer.from_pretrained(str(base_model), local_files_only=True, trust_remote_code=False)


def sample_balanced(rows: list[dict], max_negative_ratio: float | None, seed: int = 42) -> tuple[list[dict], dict]:
    """Cap likely_false supervised TURNS relative to likely_true, deterministically.

    Counts the actual supervised label (human_label / label), NOT the legacy
    source=='clean_evidence' heuristic. vulnerable_fixed_pair rows are kept
    in full (they are a different task) and excluded from the ratio.
    Sampling is seeded and independent of input order.
    """
    import random
    triage = [r for r in rows if r.get('sample_kind') == 'triage_finding']
    pairs = [r for r in rows if r.get('sample_kind') != 'triage_finding']

    def label_of(r):
        return r.get('human_label') or r.get('label')

    pos = [r for r in triage if label_of(r) == 'likely_true']
    neg = [r for r in triage if label_of(r) == 'likely_false']
    other = [r for r in triage if label_of(r) not in ('likely_true', 'likely_false')]
    manifest = {'total_input': len(rows), 'positive_turns': len(pos),
                'negative_turns': len(neg), 'other_turns': len(other),
                'pair_turns': len(pairs), 'ratio_cap': max_negative_ratio,
                'seed': seed, 'skipped': []}
    # Canonical order by id first: sampling must not depend on input order.
    pos.sort(key=lambda r: str(r.get('id')))
    neg.sort(key=lambda r: str(r.get('id')))
    if max_negative_ratio is None:
        chosen = pos + neg + other + pairs
        manifest['chosen_positive'] = len(pos)
        manifest['chosen_negative'] = len(neg)
    else:
        rng = random.Random(seed)
        rng.shuffle(pos)
        rng.shuffle(neg)
        allowed = math.floor(len(pos) * max_negative_ratio)
        for r in neg[allowed:]:
            manifest['skipped'].append({'id': r.get('id'), 'reason': 'negative_ratio_cap'})
        chosen = pos + neg[:allowed] + other + pairs
        manifest['chosen_positive'] = len(pos)
        manifest['chosen_negative'] = min(len(neg), allowed)
    chosen.sort(key=lambda r: str(r.get('id')))
    rng2 = random.Random(seed + 1)
    rng2.shuffle(chosen)  # deterministic given id-sorted canonical order
    manifest['chosen_total'] = len(chosen)
    return chosen, manifest


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('validate', 'train'):
        c = sub.add_parser(name)
        c.add_argument('--data', type=Path, required=True)
        c.add_argument('--base-model', type=Path, required=True)
        c.add_argument('--max-length', type=int, default=4096)
        c.add_argument('--max-negative-ratio', type=float, default=None,
                       help='Cap likely_false supervised turns relative to likely_true (seeded, order-independent)')
        c.add_argument('--sampling-manifest', type=Path, default=None,
                       help='Write the actual sampled-turn manifest here')
        if name == 'validate':
            c.add_argument('--limit', type=int, default=3)
        else:
            c.add_argument('--output', type=Path, required=True)
            c.add_argument('--epochs', type=float, default=1.0)
            c.add_argument('--rank', type=int, choices=(16, 32), default=16)
            c.add_argument('--accumulation', type=int, default=8)
            c.add_argument('--learning-rate', type=float, default=2e-4)
    a = p.parse_args(argv)
    try:
        rows = load_sft(_absolute(str(a.data)))
        rows, sampling = sample_balanced(rows, a.max_negative_ratio)
        if a.sampling_manifest:
            a.sampling_manifest.parent.mkdir(parents=True, exist_ok=True)
            a.sampling_manifest.write_text(json.dumps(sampling, ensure_ascii=False, indent=2), encoding='utf-8')
        if a.command == 'validate':
            tokenizer = _base_tokenizer(_absolute(str(a.base_model), directory=True))
            samples = []
            for row in rows[:max(1, a.limit)]:
                turns = _supervised_turns(tokenizer, row, a.max_length)
                for t in turns:
                    samples.append({'id': t['id'], 'tokens': t['tokens'],
                                    'supervised_tokens': t['supervised_tokens'],
                                    'label_tokens_ok': sum(1 for x in t['labels'] if x != -100) == t['supervised_tokens']})
            print(json.dumps({'command': 'validate', 'total_records': len(rows),
                              'tokenizer': str(a.base_model), 'samples': samples,
                              'sampling': sampling,
                              'output_isolation': 'train command refuses non-empty output dir'},
                             ensure_ascii=False, indent=2))
            return 0
        # train: new output dir only
        output = Path(a.output).absolute()
        if output.exists() and any(output.iterdir()):
            raise DatasetError('SFT adapter output must be new or empty; existing artifacts will not be overwritten')
        import torch
        import transformers
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        if not torch.cuda.is_available():
            raise DatasetError('NF4 QLoRA needs a local CUDA environment')
        base = _absolute(str(a.base_model), directory=True)
        tokenizer = _base_tokenizer(base)
        examples, lengths = [], []
        for row in rows:
            for t in _supervised_turns(tokenizer, row, a.max_length):
                examples.append({k: t[k] for k in ('input_ids', 'attention_mask', 'labels')})
                lengths.append({'id': t['id'], 'tokens': t['tokens'], 'supervised_tokens': t['supervised_tokens']})
        dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        quant = transformers.BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4',
                                                bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=dtype)
        config = transformers.AutoConfig.from_pretrained(str(base), local_files_only=True, trust_remote_code=False)
        model = transformers.AutoModelForCausalLM.from_pretrained(
            str(base), config=config, local_files_only=True, trust_remote_code=False,
            quantization_config=quant, device_map={'': 0}, torch_dtype=dtype)
        model.config.use_cache = False
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
        model = get_peft_model(model, LoraConfig(r=a.rank, lora_alpha=a.rank * 2, lora_dropout=0.05,
                                                target_modules=['q_proj', 'k_proj', 'v_proj', 'o_proj'],
                                                bias='none', task_type='CAUSAL_LM'))
        args = transformers.TrainingArguments(
            output_dir=str(output), per_device_train_batch_size=1,
            gradient_accumulation_steps=a.accumulation, num_train_epochs=a.epochs,
            learning_rate=a.learning_rate, gradient_checkpointing=True,
            fp16=dtype == torch.float16, bf16=dtype == torch.bfloat16,
            report_to=[], save_strategy='epoch', logging_steps=1, seed=42,
            remove_unused_columns=False)
        from transformers import Trainer
        from transformers.data.data_collator import default_data_collator
        Trainer(model=model, args=args, train_dataset=examples,
                data_collator=default_data_collator).train()
        model.save_pretrained(str(output), safe_serialization=True)
        tokenizer.save_pretrained(str(output))
        print(json.dumps({'adapter': str(output), 'training_turns': len(examples),
                          'epochs': a.epochs, 'learning_rate': a.learning_rate,
                          'base_model_sha': hashlib.sha256(str(base).encode()).hexdigest()[:12],
                          'sampling_manifest': str(a.sampling_manifest) if a.sampling_manifest else None,
                          'evaluation_gate': 'NOT RUN; compare on sft_eval.jsonl before deployment'},
                         ensure_ascii=False, indent=2))
        return 0
    except (DatasetError, OSError, ValueError) as exc:
        print(json.dumps({'error': f'{type(exc).__name__}: {exc}'}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
