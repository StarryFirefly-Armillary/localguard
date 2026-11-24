# LocalGuard 模型训练「燃料不足」问题分析

> 交接文档：供其他 AI 独立分析。本文把**客观事实**与**我的判断**明确分开，所有数字均来自本地 artifact 复核（2026-11-24）。
> 工作区：`E:/LocalMD`；训练相关文件在 `E:/LocalAI/LocalGuard/`。

---

## 一、背景：这个模型是干什么的

LocalGuard 是一个本地代码安全审计工具。架构纪律：

- **发现**来自确定性扫描器（patterns/semgrep/gitleaks 等），模型**不能**产生可信行号、增删发现或改严重度。
- **模型**（`Qwen3.5-4B-Q4_K_M-localguard-tuned.gguf`）只做 advisory 的两件事：
  1. 给已验证发现写中文解释 + 修复建议；
  2. 分诊（triage）：给每条发现打 `likely_true` / `likely_false` / `uncertain` verdict，只用于**排序和问题卡片徽章**，不删发现。

当前用户关注的痛点：**模型分诊的误报**——把安全代码判成 `likely_true`（"可能是真的"），干扰用户对报告的判断。

---

## 二、客观事实（全部可复核）

### 2.1 当前已部署模型

- 基座：`Qwen/Qwen3.5-4B`（Apache-2.0，4B dense，Q4_K_M 约 2.7GB）
- 微调方式：QLoRA，**正负平衡数据**，已 merge → GGUF → 部署在 `localguard.local.json` 的 `model_path`
- 部署门槛：8gb 档校验要求文件名含 `Qwen3.5-4B` 与 `Q4`（`model.py` 的 `_qwen4b`/`_q4`）
- 显存：RTX 5070 Laptop 8GB，模型加载约 3.2GB；外部 llama-server 常驻于 `127.0.0.1:17865`

### 2.2 上一次训练的门控结果（唯一一次通过的）

文件：`E:/LocalAI/LocalGuard/evaluation/balanced-1to1/gate-result.json`

| 指标 | 微调前(before) | 微调后(after) |
|---|---|---|
| samples | 7 | 7 |
| detection_accuracy | 0.714 | 0.857 |
| precision | 0.5 | 0.667 |
| false_positive_rate | 0.4 | 0.2 |
| exact_line_accuracy | 0.5 | 0.5 |
| cwe_accuracy | 0.0 | 0.0 |
| AUC | 0.7 | 0.85 |
| confusion | tp2 fp2 tn3 fn0 | tp2 fp1 tn4 fn0 |

`passed: true`，最小 FPR 改善阈值 0.001。

**注意**：FPR 从 0.4→0.2 实际上是 **fp 从 2 条变 1 条**（7 条样本），即**单条样本的差别**。

### 2.3 训练数据现状（严格 provenance 校验）

数据源（`E:/LocalMD/.localguard/curation/`）：

| 源 | 条数 | 校验要求 |
|---|---|---|
| cve_patch.jsonl | 6 | 真实 Git commit(40/64位) + CVE + 函数代码与 pinned blob 逐字节匹配 |
| security_dialogue.jsonl | 6 | sha256 锚定的真实 advisory 文件 + CVE/事件 ID |
| tool_call.jsonl | 6 | 真实 view_file + 扫描日志、session_hash 匹配 |
| clean_evidence.jsonl | 23 | 真实 view_file 零发现 + 真实 patterns 零发现扫描 artifact + hash 匹配 |
| extended/security_dialogue.jsonl | 9 | 同 security_dialogue |
| **合计** | **41** | 其中正样本 18（6+6+6）、负样本 23 |

人工反馈（`state.sqlite3` 的 `reviews` 表）：**仅 2 条，均为 `false_positive`**。

### 2.4 训练约束（已实测）

- 8GB 显存全空时：基座 4bit 加载 3.31GB；`--no-gradient-checkpointing --max-length 256` = 7.05GB / 5.89s 每步，可行
- 有 checkpointing 时 512tok ≈ 44s/步（数小时）；关 checkpointing + 320tok = 8.08GB 临界；512tok = OOM
- `--max-negative-ratio`：控制训练时正负抽样比例
- 上次成功训练：1:1 比例（11 正 + 12 负、23 turn），约 4 分钟，loss 收敛

**历史教训**：第一次用 4:1 负样本比例，结果 FPR 0.4→0.0 但 `exact_line_accuracy` 0.5→0.0（过度拒报，行号准确率归零），门控失败；改 1:1 后才通过。

### 2.5 已完成的扩容试点（未用于训练）

我以大模型身份写了 **11 个"看起来可疑但实际安全"的干净代码样本**（参数化 SQL、环境变量读密钥、白名单路径、HTML 转义、安全 JSON、hmac 常量比较、JS 白名单重定向、Java PreparedStatement、Go html/template、PDO 绑定等），放在 `E:/LocalMD/.workbuddy/pilot_clean/`。

- 走真实 `view_file` + patterns 零发现扫描 + sha256 artifact + `validate_record` 严格校验
- 结果：**11/11 全部通过，0 拒绝**；与现有 23 条零重复；未触碰 held-out
- 产物：`pilot_clean_evidence.jsonl`（11 行）+ 11 个扫描 artifact
- 加入后：正 18 / 负 34 = **1.89:1**（原来是 1.28:1）

**试点没有启动训练，没有改动正式 curation 数据。**

### 2.6 数据生产路径（关键设计）

`localguard/training.py` 的校验是**刻意的反幻觉/反投毒设计**：

- `cve_patch`：必须锚定真实 Git commit + CVE，函数代码与 pinned Git blob 逐字节匹配（`not invented code`）
- `security_dialogue`：必须 sha256 校验的真实 advisory 文件
- `tool_call`/`clean_evidence`：必须真实 view_file 日志 + 真实扫描日志 + session_hash 匹配

因此：**模型凭空写的漏洞标注会被全部拒绝**。合法扩容只有两条路：
1. 大模型写**干净代码**当候选，真实性由扫描器日志担保（已试点成功）；
2. 从真实 CVE 仓库抓漏洞，大模型只写解释文本（本地目前只有 6 条 cve_patch，这条路未走）。

`scripts/collect_clean_evidence.py` 是现有合法负样本生成器（硬编码 `fixtures/clean` + train-split safe implementations）；试点用了复刻其逻辑的独立脚本。

---

## 三、我的判断（非事实，请独立验证）

### 3.1 为什么我认为"燃料不足"

1. **held-out 只有 7 条，且正样本只有 2 个 CVE**（CVE-2020-7598 / CVE-2021-44906），一个负例就能翻转 FPR。上轮的改善是 fp 2→1，落在统计噪声范围内。
2. **训练数据总共 41 条**，其中与分诊误报直接相关的负样本 23 条，人工反馈只有 2 条。对 4B 模型做 QLoRA，这个规模很容易过拟合到样本的表面模式。
3. **cwe_accuracy 一直 0.0**：模型在门控样本上根本没学会判 CWE，说明数据量/质量不足以学到语义。

### 3.2 为什么我建议"暂缓重训"

- 在 7 条 held-out 上，新增 11 条负样本带来的变化**无法可靠验证**——门控通过也可能只是噪声。
- 比例从 1.28:1 升到 1.89:1，介于"4:1 训出过度拒报"与"1:1 通过"之间，有温和的过度拒报风险。
- 重训需用户腾空显存（当前 UI 服务占 5.4GB），且约 4 分钟训练 + 评估时间。

### 3.3 我排除的方向（请复核是否合理）

- **训练不能提速**：QLoRA 只改权重值，不改架构/参数量/量化位数，推理计算量不变。提速要靠缩输出、减解释条数、缓存（已做过）。
- **换更小/更强模型不划算**：通用 coding 模型（SWE-bench 高分）考的是写代码/改 bug，不是"对已验证发现做中文解释 + 分诊"；且会丢失当前正负平衡调校。Qwen2.5-Coder-3B 是 Qwen Research License（仅非商用），与项目可再分发定位冲突。

---

## 四、希望其他 AI 分析的问题

1. **在 7 条 held-out 的现状下，有没有统计上更可靠的评估方法**？（例如对现有样本做 bootstrap 置信区间，或设计分层抽样）上轮 FPR 0.4→0.2 究竟是真实改善还是噪声？
2. **11 条试点负样本值不值得现在就用**？是先用 `--max-negative-ratio 1.0` 抽样到 1:1 跑一轮看门控，还是继续攒到 50+ 再训？
3. **如何合法扩大正样本**？目前只有 6 条 cve_patch，且 provenance 校验极严。从公开 CVE 仓库批量生成合规 cve_patch 记录是否可行？有无工具链建议？
4. **人工反馈回流机制**：`reviews` 表只有 2 条。有没有办法把 UI 复核行为更自然地转成训练燃料（当前 `ingest_logs()` 依赖 `location_rejected` 日志，而该日志在库里为 0）？
5. **我的判断有没有盲点**？特别是"暂缓重训"这个结论——是否存在低成本、可验证的方式证明现在训就有收益？

---

## 五、 annex：关键文件清单

| 用途 | 路径 |
|---|---|
| 当前门控结果 | `E:/LocalAI/LocalGuard/evaluation/balanced-1to1/gate-result.json` |
| held-out 样本 | `E:/LocalAI/LocalGuard/data/heldout.jsonl`（7 条）|
| train 样本 | `E:/LocalAI/LocalGuard/data/train.jsonl` |
| 训练数据（正式） | `E:/LocalMD/.localguard/curation/*.jsonl`（41 条）|
| 试点负样本 | `E:/LocalMD/.workbuddy/pilot_clean/pilot_clean_evidence.jsonl`（11 条）|
| 试点采集脚本 | `E:/LocalMD/.workbuddy/bench_model/collect_pilot.py` |
| 正式采集脚本 | `E:/LocalMD/scripts/collect_clean_evidence.py` |
| 训练 CLI | `E:/LocalMD/scripts/train_adapter.py`（validate/train/evaluate/merge）|
| 校验逻辑 | `E:/LocalMD/localguard/training.py` |
| 环境与限制记录 | `E:/LocalMD/.workbuddy/memory/2026-11-20.md`（第 74-80 行训练成功记录）|
| 试点记录 | `E:/LocalMD/.workbuddy/memory/2026-11-23.md`（试点与比例分析）|

> 提示：读 `data/heldout.jsonl` 时 Git Bash 的 `/e/LocalAI/...` 路径与 Windows Python 不互通，需用 `E:/LocalAI/...` 形式或设置 `LG_BASE=E:/LocalAI/LocalGuard`。
