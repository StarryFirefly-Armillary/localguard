"""Short benchmark: VRAM peak + step time with gradient checkpointing ON.

Run with the train-env interpreter. Measures several sequence lengths so the
training window can be chosen from real numbers instead of guesses.
"""
import os
import time

os.environ['HF_HUB_OFFLINE'] = '1'
os.environ['TRANSFORMERS_OFFLINE'] = '1'

import torch
import transformers
from peft import LoraConfig, get_peft_model
from transformers import BitsAndBytesConfig

# Local training paths are machine-specific: set LG_BASE_MODEL to your own
# checkout. The default is a relative placeholder, never a personal path.
BASE = os.environ.get('LG_BASE_MODEL', 'models/base-model')


def main():
    q = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type='nf4',
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
    )
    cfg = transformers.AutoConfig.from_pretrained(BASE, local_files_only=True, trust_remote_code=False)
    cls = (transformers.AutoModelForImageTextToText
           if cfg.model_type in ('qwen3_5', 'qwen3_5_moe')
           else transformers.AutoModelForCausalLM)
    model = cls.from_pretrained(
        BASE, config=cfg, local_files_only=True, trust_remote_code=False,
        quantization_config=q, device_map={'': 0}, torch_dtype=torch.bfloat16,
    )
    model = get_peft_model(model, LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05,
        target_modules=['q_proj', 'k_proj', 'v_proj', 'o_proj'],
        bias='none', task_type='CAUSAL_LM',
    ))
    model.config.use_cache = False
    model.gradient_checkpointing_enable()
    print('BENCH result loaded_base_GB', round(torch.cuda.memory_allocated() / 1e9, 2), flush=True)

    for length in (384, 512, 640, 768):
        try:
            ids = torch.randint(0, 1000, (1, length), device='cuda')
            torch.cuda.synchronize()
            torch.cuda.reset_peak_memory_stats()
            t = time.time()
            out = model(input_ids=ids, labels=ids)
            out.loss.backward()
            torch.cuda.synchronize()
            print(
                f'BENCH result ckpt {length}tok sec {round(time.time() - t, 1)} '
                f'peakGB {round(torch.cuda.max_memory_allocated() / 1e9, 2)}',
                flush=True,
            )
            model.zero_grad(set_to_none=True)
            torch.cuda.empty_cache()
        except torch.OutOfMemoryError:
            print(f'BENCH result OOM {length}tok', flush=True)
            torch.cuda.empty_cache()
            break


if __name__ == '__main__':
    main()
