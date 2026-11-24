"""Paired base-vs-SFT-adapter evaluation on gold_v1 sft_eval.jsonl.

STRICT pairing: one process, same FP16/NF4 base weights, same prompts, same
decode params. Loads base once -> evaluates -> attaches adapter -> evaluates.
This avoids comparing a GGUF Q4 baseline against an HF adapter (not paired).

Outputs a JSON artifact; prints only a short summary. No deployment action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

VERDICTS = {'likely_true', 'likely_false', 'uncertain'}


def _metrics(results: list[dict]) -> dict:
    tp = fp = tn = fn = unc = fail = 0
    for r in results:
        v = r.get('verdict')
        if v is None:
            fail += 1
        elif v == 'uncertain':
            unc += 1
        else:
            pos = r['expected'] == 'likely_true'
            if v == 'likely_true':
                tp += pos; fp += not pos
            else:
                fn += pos; tn += not pos
    n = len(results)
    return {'samples': n, 'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'uncertain': unc, 'parse_failures': fail,
            'accuracy': round((tp + tn) / n, 4) if n else None,
            'precision': round(tp / (tp + fp), 4) if tp + fp else None,
            'recall': round(tp / (tp + fn), 4) if tp + fp + fn + tn else None,
            'fpr': round(fp / (fp + tn), 4) if fp + tn else None,
            'json_success_rate': round((n - fail) / n, 4) if n else None}


def _generate(model, tokenizer, messages: list[dict], max_new_tokens=160) -> dict:
    prompt = tokenizer.apply_chat_template(messages, add_generation_prompt=True,
                                           tokenize=False, enable_thinking=False)
    ids = tokenizer(prompt, add_special_tokens=False, return_tensors='pt').to(model.device)
    with __import__('torch').inference_mode():
        out = model.generate(**ids, max_new_tokens=max_new_tokens, do_sample=False,
                             pad_token_id=tokenizer.pad_token_id)
    text = tokenizer.decode(out[0][ids['input_ids'].shape[-1]:], skip_special_tokens=True)
    try:
        data = json.loads(text)
        v = data.get('verdict')
        if v not in VERDICTS:
            v = None
    except Exception:
        v = None
    return {'verdict': v, 'raw': text[:200]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--eval', type=Path, default=ROOT / '.workbuddy/training_data/gold_v1/sft_eval.jsonl')
    p.add_argument('--base-model', type=Path, default=Path('E:/LocalAI/LocalGuard/merged-balanced-1to1'))
    p.add_argument('--adapter', type=Path, default=Path('E:/LocalAI/LocalGuard/adapter-gold-v1-1ep'))
    p.add_argument('--out', type=Path, default=ROOT / '.workbuddy/training_data/gold_v1/paired_compare.json')
    a = p.parse_args()

    rows = []
    for line in a.eval.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        expected = json.loads(r['messages'][-1]['content']).get('verdict')
        if expected in VERDICTS:  # skip cve_function_pair (no verdict)
            rows.append({'id': r['id'], 'messages': r['messages'][:-1], 'expected': expected})

    import torch
    import transformers
    from peft import PeftModel

    tokenizer = transformers.AutoTokenizer.from_pretrained(str(a.base_model), local_files_only=True)
    tokenizer.pad_token = tokenizer.pad_token or tokenizer.eos_token
    config = transformers.AutoConfig.from_pretrained(str(a.base_model), local_files_only=True)
    cls = (transformers.AutoModelForImageTextToText
           if getattr(config, 'model_type', '') in ('qwen3_5', 'qwen3_5_moe')
           else transformers.AutoModelForCausalLM)
    quant = transformers.BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4',
                                            bnb_4bit_use_double_quant=True,
                                            bnb_4bit_compute_dtype=torch.bfloat16)
    model = cls.from_pretrained(str(a.base_model), config=config, local_files_only=True,
                                quantization_config=quant, device_map={'': 0}, torch_dtype=torch.bfloat16)
    model.eval()

    base_results = []
    t0 = time.time()
    for r in rows:
        got = _generate(model, tokenizer, r['messages'])
        base_results.append({**r, **got})
    base_time = round(time.time() - t0, 2)

    model = PeftModel.from_pretrained(model, str(a.adapter))
    model.eval()
    trained_results = []
    t0 = time.time()
    for r in rows:
        got = _generate(model, tokenizer, r['messages'])
        trained_results.append({**r, **got})
    trained_time = round(time.time() - t0, 2)

    # paired flips
    flips = [{'id': b['id'], 'expected': b['expected'],
              'base': b['verdict'], 'trained': t['verdict']}
             for b, t in zip(base_results, trained_results) if b['verdict'] != t['verdict']]
    result = {
        'kind': 'gold_v1_paired_base_vs_sft',
        'warning': 'EXPLORATORY — 22 triage samples, greedy decoding, single paired run.',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'eval_sha256': hashlib.sha256(a.eval.read_bytes()).hexdigest(),
        'base_model': str(a.base_model), 'adapter': str(a.adapter),
        'adapter_sha256': hashlib.sha256((a.adapter / 'adapter_model.safetensors').read_bytes()).hexdigest(),
        'base_seconds': base_time, 'trained_seconds': trained_time,
        'base_metrics': _metrics(base_results),
        'trained_metrics': _metrics(trained_results),
        'verdict_flips': flips,
        'per_sample': [{'id': b['id'], 'expected': b['expected'],
                        'base_verdict': b['verdict'], 'trained_verdict': t['verdict'],
                        'base_raw': b['raw'], 'trained_raw': t['raw']}
                       for b, t in zip(base_results, trained_results)],
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'artifact': str(a.out),
                      'base': result['base_metrics'], 'trained': result['trained_metrics'],
                      'flips': len(flips)}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
