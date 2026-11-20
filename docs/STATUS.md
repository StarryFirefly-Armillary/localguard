# LocalGuard QLoRA adapter — 训练与门控状态

Date: 2026-11-20 (updated same day, 20:45)

## 结论

阶段 5 的配对评估门控（`localguard.training.compare_evaluations`）**已通过**，一个正负平衡的 QLoRA adapter **已训练、合并并量化为 Q4_K_M GGUF**，产品配置已指向该微调模型。运行时用 llama.cpp CUDA 13.5 版 llama-server（RTX 5070 为 Blackwell sm_120，必须 13.5 构建），已实测 8gb 档模型解释真实执行、显存占用约 3.2GB。确定性扫描器 + locations 校验层仍是可信来源，模型解释是可选增强。

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

## 运行时 llama-server：必须用 CUDA 13.5（Blackwell）

本机 GPU 是 RTX 5070 Laptop，Blackwell 架构、compute capability 12.0（sm_120）。踩过的坑与结论：

- 原先配置的 `model_binary` 指向 LM Studio 捆绑的 `llama.cpp-...-cuda12-avx2-2.79.0/llama-server.exe`，该精简后端启动即缺依赖失败，产品等待 60 秒后降级 → 报告里 `Local model explanation unavailable... timed out`，这就是"选了 8GB 但显存一点不占"的真因。
- 用户提供的 b12568 CPU 包能启动模型，但**只用 CPU**：进程占约 6.3GB 系统内存、GPU 显存 0 MiB、首次解释 >3.5 分钟，实用性差。
- 正确方案：llama.cpp **b12578** 的 `llama-b12578-bin-win-cuda-13.5-x64.zip` + `cudart-llama-bin-win-cuda-13.5-x64.zip`，两个 zip 解压到同一目录。cuda-12.4 构建早于 Blackwell、无 sm_120 内核也无 PTX，会静默回退 CPU（`--version` 正常但 `--list-devices` 为空），别选。
- 验证命令：`llama-server.exe --list-devices` 必须输出 `CUDA0: NVIDIA GeForce RTX 5070 Laptop GPU`。`--version` 正常不代表 CUDA 可用。
- 已把 `<repo>/localguard.local.json` 的 `model_binary` 指向 `<training-dir>/tools/llamacpp-cuda135/llama-server.exe`。实测 8gb 档审查：显存峰值约 3180 MiB，`coverage.model_explanation: completed`、`completed_modules` 含 `model_explanation`、解释为模型生成的中文文本，62 秒完成，结束后显存归零（`keep_model_resident: false`）。

GGUF 转换用的是 b12568 工具链（含 `llama-quantize.exe`），与运行时 b12578 属同一近期系列，Q4_K_M 格式通用。

观察：一次手动推理中，安全写法 `api_key = os.environ["API_KEY"]` 被微调模型报为 CWE-287。门控（7 样本）通过不代表全面零误报；确定性扫描器仍是报告的可信来源，模型解释保持可选。

## 与旧记录的关系

早前的 `adapter-r16` 只训练 5 步、零负样本，门控失败（`false_positive_rate: no measurable improvement`），**未部署**。本记录取代该结论：问题被诊断为数据失衡而非方法不可行，补齐真实负样本并平衡后门控通过。

## 智能排除与 LLM 分诊（2026-11-21 凌晨）

用户质疑：审查本项目报出 130 条问题无法逐条人工判断，而 LLM 只写解释不做甄别。为此新增两层能力。

### 智能排除（auto_exclude，默认开启）

`localguard/discovery.py`，跨生态通用、不硬编码任何项目特定路径。三类信号：
1. 常规测试/夹具/生成目录名（pytest/jest/Go/Rust/Maven 等：`tests/`, `__tests__`, `spec/`, `fixtures/`, `mocks/`, `samples/`, `coverage/`, `dist/` 等）；
2. 文件前 12 行的自声明（`STATIC FIXTURE ONLY` / `DO NOT EXECUTE` / `synthetic example` 等），即使样本不在测试目录也能识别；
3. 已知非源码产物（lockfiles、`.min.js` 等）。

排除结果按原因汇总进 warnings，用户可 `auto_exclude: false` 关闭，或用 `exclude_paths` 追加。保护机制：当审查目标本身就是测试目录（`is_test_root`），或目录里 ≥80% 文件都是自声明样本时，不做自动排除——明确指向样本库的审查不该被清空。实测审查本项目：130 → 0，且 warning 写明"conventional test/fixture directory: 68 file(s)"。

### LLM 分诊（model_triage，默认开启）

`explain_issues(..., triage=True)` 在**同一次模型调用**里让模型对每条已验证发现额外输出 `verdict`（likely_true / likely_false / uncertain）+ `confidence` + `reason`。

严格边界：不删除任何 issue、不改严重度、不写行号（reason 中的坐标会被脱敏）；每条判断写 `model_triage` 审计日志；人工复核推翻时写 `human_review.overruled_model` 并标记 `triage.overridden`。模型分诊失败时**回退到纯解释**，绝不因为分诊错误丢掉确定性报告。UI 增加分诊徽章与"可能是真的/可能误报/不确定"筛选。

实测（8gb CUDA、55 条 fixture 命中）：`coverage.model_triage: completed`，55 条全部标为 `likely_false`，理由如"源文件明确标记为静态测试用占位符…故意放置的测试数据"。这证明模型确实在做真假甄别，而非只润色文字。

测试：`tests/test_discovery_and_triage.py`，全套 352 passed。
