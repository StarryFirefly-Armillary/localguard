# LocalGuard QLoRA adapter — 训练与门控状态

Date: 2026-11-20 (updated same day, 20:45)

## 结论

阶段 5 的配对评估门控（`localguard.training.compare_evaluations`）**已通过**，一个正负平衡的 QLoRA adapter **已训练并合并**。但合并产物是 Hugging Face FP16 格式；产品运行时用的是 GGUF + llama-server，因此还需要一次 GGUF 量化才能替换现有运行时模型。在量化完成前，交付边界仍是确定性扫描器 + locations 校验层，模型解释保持可选。

## 已实际完成的工作

- 显存条件：把本机 8GB GPU 腾到约 7GB 空闲后，用无 gradient checkpointing（参考 kernel 下快得多）在 256-token 窗口训练；实测该配置显存峰值 7.05GB、约 5.9s/微步。
- 数据：全部 41 条记录通过 `train_adapter.py validate`；训练窗口内可用 57 turn（11 正 + 46 负）。第一轮因负样本 4:1 失衡导致行号引用退化，随后加 `--max-negative-ratio 1.0` 做 1:1 平衡（11 正 + 12 负，23 turn）。
- 训练：`adapter-balanced-1to1`，rank 16、2 epochs、accumulation 4、256 token、loss 收敛。注入了 `--no-gradient-checkpointing` / `--max-length` / `--skip-oversized` / `--max-negative-ratio` 四个显式开关，默认行为不变。
- 门控（`<training-dir>/evaluation/balanced-1to1/gate-result.json`）：`passed: true`，`reasons: []`。

| 指标 | before（基座） | after（adapter） |
|---|---|---|
| detection_accuracy | 0.714 | **0.857** |
| detection_precision | 0.5 | **0.667** |
| false_positive_rate | 0.4 | **0.2** |
| exact_line_accuracy | 0.5 | 0.5（不退化） |
| tool_format_success | 1.0 | 1.0（不退化） |
| AUC | 0.7 | **0.85** |

- 合并：`train_adapter.py merge` 在门控 `passed: true` 后才执行，产出 `<training-dir>/merged-balanced-1to1`（FP16 safetensors，约 9GB）。已用 4-bit NF4 真实加载并生成，确认不是空壳。

## 仍待完成：GGUF 量化

产品运行时的 `model_path` 指向 GGUF。要把合并模型接入，需要：

1. 用与所用 llama.cpp 后端兼容的 `convert_hf_to_gguf.py`（新版依赖 `conversion/` 模块包）把 FP16 safetensors 转成 F16 GGUF；
2. 用官方 `llama-quantize`（`llama-b*-bin-win-cpu-x64.zip` 内含）量化到 Q4_K_M；
3. 把配置里的 `model_path` 指向新 GGUF，再跑 `scripts/verify_local_model.py --tier 8gb` 验证。

本次没有完成量化：官方 Windows 二进制压缩包下载被网络限速（10 分钟仅 ~13MB、未完成），且 Qwen3.5 多模态架构在捆绑后端（llama.cpp 2.79.0）的兼容性未验证。没有拿未验证的转换产物冒充可用模型。

## 与旧记录的关系

早前的 `adapter-r16` 只训练 5 步、零负样本，门控失败（`false_positive_rate: no measurable improvement`），**未部署**。本记录取代该结论：问题被诊断为数据失衡而非方法不可行，补齐真实负样本并平衡后门控通过。
