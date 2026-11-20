# 渐进式模型训练指南

LocalGuard 的设计是「确定性优先」：**模型不是必需品**。你可以按下面四个阶段逐步升级，每一阶段都能独立使用、随时停下。

```
阶段 0  纯规则（无需任何模型）        ← 开箱即用，已验证
阶段 1  现成 GGUF（下载即可，不训练）  ← 想让对话模式/解释更自然
阶段 2  数据回流（用真实交互攒样本）    ← 不训练，只积累高质量数据
阶段 3  QLoRA 微调 + 门控             ← 只有门控通过才合并部署
```

---

## 阶段 0：纯规则，不需要模型（默认）

默认配置 `model_tier: "rules"` 即可，**仓库不含也不需要任何模型文件**。

- 完整链路可用：确定性扫描 → locations 校验 → 结构化报告 → UI 深链。
- 已实测：无模型时对内置 fixtures 审查得到 38 条 issue，`vulnerable.c:4` 等定位准确，`status: completed`。
- 差别仅在报告解释是规则生成的确定性文本；`coverage.model_explanation` 不出现是正常现象。
- 表单模式与 MCP `audit_repository` 本来就不经过 LLM；`rules` 下对话模式退化为确定性路由。

验证命令：

```bash
python -m localguard --config <你的配置> audit <目标目录> --depth quick --scanners patterns
python -m localguard --config <你的配置> doctor        # 检查路径/扫描器/grammar/模型是否就绪
```

> 注意：`doctor` 要求配置里的 `allowed_roots` 真实存在。示例模板用的是占位路径 `C:/work/projects`，先改成你自己的目录。

---

## 阶段 1：接入现成模型（下载，不训练）

想让**对话模式**能自主编排工具、报告解释更自然，接入一个本地 GGUF 即可，无需训练。

1. 准备兼容 llama-server 的二进制，以及 `Qwen3.5-4B-Q4_K_M.gguf`（8GB 档；4GB 档用更小的 Q4 模型）。
2. 在配置中填写：

```json
{
  "model_tier": "8gb",
  "model_binary": "C:/path/to/llama-server.exe",
  "model_path": "C:/path/to/Qwen3.5-4B-Q4_K_M.gguf",
  "model_library_dirs": ["C:/path/to/cuda-vendor-libs"],
  "mmproj_path": "C:/path/to/mmproj-....gguf"
}
```

3. 验证真实生成是否可用：

```bash
python scripts/verify_local_model.py --config <你的配置> --target <允许的目录> --tier 8gb
python scripts/verify_model_explanations.py     # 用 localguard.local.json 的路径
```

安全约束（源码强制）：模型端点必须是 loopback `/v1`，`8gb` 档只接受显式命名的 Qwen3.5-4B Q4；OOM / 不可用都会以可读错误返回，不伪装成成功。模型**永远不产生被信任的行号**——所有行号仍来自 AST / 扫描器并经校验层。

---

## 阶段 2：数据回流（不训练，只积累）

这是"慢慢把模型训练好"的核心：**先用系统跑真实任务，把高质量交互沉淀成训练数据**。仓库已提供完整工具链。

1. **采集真实工具轨迹**：用真实仓库/代码跑审查，服务端会把每次 MCP/UI 调用写入 `.localguard/state.sqlite3` 的 `tool_call` / `tool_evidence` / `location_validated` / `location_rejected` 日志。
2. **整理三层数据**（每层缺一不可）：
   - `cve_patch`：真实 CVE 修复提交的三元组 —— `python scripts/curate_cve_data.py build`
   - `security_dialogue`：有真实来源的 OWASP Top 10 多语言样本 —— `python scripts/extend_owasp_data.py build`
   - `tool_call`：从 genuine registry 日志构造的 `view_file` → issue 轨迹 —— `python scripts/collect_tool_data.py --curation <目录>`
   - 干净代码负样本：`python scripts/collect_clean_evidence.py`（生成 issues=[] 的 `clean_evidence`，带真实日志佐证）
3. **校验数据**（`--data` 必须是**绝对路径**）：

```bash
python scripts/train_adapter.py validate \
  --data <abs>/cve_patch.jsonl <abs>/security_dialogue.jsonl <abs>/tool_call.jsonl [abs]/clean_evidence.jsonl
```

   - 校验器严格检查来源（真实 commit/advisory/Git 对象）、工具日志哈希、行号一致性；合成/测试 fixture 一律拒绝。
   - 负样本来自 genuine 零发现扫描，不能手写 `issues: []` 蒙混。

**持续积累的做法**：把日常审查目标从 fixtures 换成你真实有权使用的代码库，定期跑 `collect_tool_data.py` 与 `collect_clean_evidence.py` 扩充数据集。数据越多、来源越真实，阶段 3 才会真正改善。

---

## 阶段 3：QLoRA 微调 + 门控（达标的唯一路径）

准备环境（需要联网下载官方依赖与基座权重，约 10GB，落到独立目录）：

```bash
python scripts/bootstrap_training.py all     # 创建 train-env、安装 torch/CUDA/PEFT、下载 Qwen3.5-4B 可训练权重
```

> **默认训练根目录由环境变量 `LOCALGUARD_TRAIN_ROOT` 决定**（默认 `C:/LocalGuard/training`）。想放在别处先设置它，脚本里已无本机绝对路径。

准备数据并训练：

```bash
python scripts/prepare_training_data.py --curation <curation目录> --base-model <base-model目录> --output <data目录>

python scripts/train_adapter.py train \
  --data <data目录>/train.jsonl <curation>/clean_evidence.jsonl \
  --base-model <base-model目录> --output <新adapter目录> \
  --rank 16 --epochs 2 --gradient-accumulation 8
```

关键开关：
- `--no-gradient-checkpointing`：attention kernel 无优化实现时更快，但 8GB 可能 OOM；先确认显存余量。实测本设备 256 token 峰值 7.05GB、320 token 8.08GB（临界），512 token OOM。
- `--max-length N`：低于 4096 时截断最早的证据 token，但**永不截断监督答案**。
- `--skip-oversized`：监督答案放不进窗口时跳过该 turn（记入 training manifest），而非让整个数据集失败。
- `--max-negative-ratio R`：把干净负样本 turn 数限制为正样本的 R 倍。**建议 1.0**——实测 4:1 失衡会让模型过度学会拒报、导致行号引用退化；1:1 才通过门控。
- 默认 `gradient_checkpointing=True` 最省显存。

**配对评估（不可跳过）**：

```bash
python scripts/evaluate_holdout.py                         # base 生成 before.json
LOCALGUARD_EVAL_ADAPTER=<新adapter目录> \
  LOCALGUARD_EVAL_OUT=<输出目录> python scripts/evaluate_holdout.py   # adapter 生成 after.json

python scripts/train_adapter.py evaluate \
  --before <输出目录>/before.json --after <输出目录>/after.json
```

门控要求：误报率（FPR）至少绝对下降 0.001，且准确率/CWE/行号/tool 格式/AUC 均不退步。**只有 `passed: true` 才能合并**：

```bash
python scripts/train_adapter.py merge --before ... --after ... \
  --base-model <base> --adapter <新adapter> --output <merged目录>
```

---

## 当前 adapter 的真实状态（别跳过）

仓库**没有**部署任何微调 adapter 到运行时（GGUF 尚未生成），但阶段 5 的门控本身**已经通过**。处理记录见 `docs/STATUS.md`：

- 早前的 `adapter-r16` 只训练 5 步、零负样本，门控失败（`false_positive_rate: no measurable improvement`）——问题被诊断为**数据失衡**而非方法不可行。
- 腾空显存后，用无 checkpointing + 256-token 窗口 + 正负 1:1 平衡数据重训，`adapter-balanced-1to1` 的门控 `passed: true`：FPR 0.4→0.2、AUC 0.7→0.85，检测准确率 0.714→0.857，行号引用与 tool 格式均不退化。
- 从未放宽门控、也从未用合成预测刷指标；`train_adapter.py merge` 只在 `passed: true` 后才执行。
- 合并产物是 FP16 safetensors（已验证可加载、可生成），但产品运行时需要 GGUF。还差一次 HF→GGUF 转换 + Q4 量化（见 `docs/STATUS.md` 的剩余步骤）才算真正替换运行时模型。

## 一句话总结

普通使用者：**不需要模型，clone 后改配置就能用**。
想让模型更好：**先用起来攒真实数据（阶段 2），再慢慢训练并通过门控（阶段 3）**，任何一步都可停下且不影响核心审查能力。
