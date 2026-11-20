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

## checkpointing + 更大窗口的探索（2026-11-20 晚，用户腾空 8GB 显存后）

用户把显存彻底腾空（实测 `memory.used = 0 MiB`）并要求尝试打开 gradient checkpointing 训练以提高素质。先做了短基准（`scripts/bench_ckpt_windows.py`），一个重要发现是：**checkpointing 在这个 Qwen3.5 多模态模型上并不省显存**，各窗口峰值 384tok=9.45GB / 512tok=11.5GB / 640tok=13.56GB / 768tok=15.6GB，都是靠 Windows WDDM 共享内存才没 OOM。checkpointing 本身数学无损，不直接改变模型质量；真正可能提高素质的是更大窗口带来的更完整证据和更多样本。

各窗口的样本保留情况（1:1 平衡）：256tok=23 turn、384tok=52、512tok=59、640tok=71。选 384tok（样本翻倍、峰值相对最低、7.6s/微步）做了三次训练，门控结果：

| adapter | 配置 | passed | 结果 |
|---|---|---|---|
| `adapter-balanced-1to1`（上一轮） | 256tok，无 ckpt，1:1 | **true** | FPR 0.4→0.2，行号 0.5 不退化 |
| `adapter-ckpt384` | 384tok，ckpt，2ep，1:1 | false | 全部输出空，TP 2→0，AUC 退化 |
| `adapter-ckpt384-e1` | 384tok，ckpt，1ep，1:1 | false | 同上（与 ep 数无关） |
| `adapter-ckpt384-r03` | 384tok，ckpt，1ep，负样本 0.3 | false | 检测恢复（acc 0.857），但唯一命中行号 74 vs GT 73，`exact_line_accuracy` 0.5→0.0 |

根因诊断：384 窗口保住了 18 个 `security_dialogue` turn，其监督目标是 `{"safe_implementation": ...}` / `{"attack_demo": ...}` 这类**非检测格式**长 JSON；真正的检测正样本只有 8 个（cve_patch 4 + tool_call 4），却被最多 26 个空 issues 负样本淹没，模型学成"一律输出空"（降 ep 无效，降负样本比例才恢复检测）。最后一次仅差一个 off-by-one 行号；7 样本的 `exact_line_accuracy` 对该类偏移极敏感。

**决定：不再继续调参**（避免针对 7 个样本过拟合）。部署采用唯一有门控背书的 `adapter-balanced-1to1` 合并产物。三次失败实验的完整预测与门控 JSON 保留在 `<training-dir>/evaluation/ckpt384*/`，作为可复现记录。

## GGUF 量化（本轮完成转换工具链准备）

产品运行时的 `model_path` 指向 GGUF。转换链本轮已打通：

1. 用户提供了官方 `llama-b12568-bin-win-cpu-x64.zip`，含 `llama-quantize.exe` / `llama-server.exe`，已解压到 `<training-dir>/tools/llamacpp/`。
2. 从 llama.cpp master 下载 `conversion/`（130 模块）和配套 `gguf-py/`（11 模块）到 `<training-dir>/`（用 `PYTHONPATH` 优先加载，不污染 train-env）。关键点：PyPI 的 gguf 0.19.0 缺少新版 `MODEL_TENSOR.ATTN_QKV_GATE`，必须用 master 的 gguf-py，否则 `conversion/qwen.py` 导入失败。
3. `convert_hf_to_gguf.py ... --dry-run` 已验证：识别 `Qwen3_5ForConditionalGeneration`、378 tensors、8.4GB F16。

## 部署完成（2026-11-20 晚）

- 转换：`convert_hf_to_gguf.py merged-balanced-1to1 --outtype f16` → `gguf-out/model-f16.gguf`（8.42GB，378 tensors）。关键：用 `PYTHONPATH=<training-dir>/gguf-py;<training-dir>` 加载 master 版 gguf-py 与 conversion 模块。
- 量化：`tools/llamacpp/llama-quantize.exe model-f16.gguf model-Q4_K_M.gguf Q4_K_M` → 2.74GB（16→5.19 BPW），另存为合规名 `Qwen3.5-4B-Q4_K_M-localguard-tuned.gguf`（8gb 档校验要求文件名含 Qwen3.5-4B 与 Q4）。
- 视觉投影：视觉权重未参与微调，复用基座同款 `mmproj-Qwen3.5-4B-BF16.gguf`；llama-server 加载确认 `loaded multimodal model` + `model loaded`。
- 产品验证：`verify_local_model.py --tier 8gb` 指向新 GGUF → `isError: false`、`native_tool_format_success: 1`、工具格式失败 0。产品 `model.py:294` 已传 `enable_thinking: false`，新模型不会陷入 thinking 模式。
- 已切换 `<repo>/localguard.local.json` 的 `model_path` 到微调 GGUF；原配置备份在 `<training-dir>/gguf-out/localguard.local.json.backup-before-tuned`。全套测试 345 passed。

注意：本项目用的是 llama.cpp **b12568** 工具链转换，而产品运行时 llama-server 是 LM Studio 捆绑的 2.79.0（更旧）。新 GGUF 已在 b12568 的 llama-server 上验证加载与推理；旧版 2.79.0 对 qwen3_5 架构的支持未在本次验证（8gb 档产品验证脚本已实际启动它并成功，见上条）。若实际使用中出现架构不兼容，回退到备份配置即可。

观察：一次手动推理中，安全写法 `api_key = os.environ["API_KEY"]` 被微调模型报为 CWE-287。门控（7 样本）通过不代表全面零误报；确定性扫描器仍是报告的可信来源，模型解释保持可选。

## 与旧记录的关系

早前的 `adapter-r16` 只训练 5 步、零负样本，门控失败（`false_positive_rate: no measurable improvement`），**未部署**。本记录取代该结论：问题被诊断为数据失衡而非方法不可行，补齐真实负样本并平衡后门控通过。
