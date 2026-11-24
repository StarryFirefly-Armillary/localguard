# LocalGuard 评估原型口径修正报告

- 日期：2026-11-24
- 对应提交：`03f90e9`（`fix(eval): 修正评估口径与检测探针提示泄漏（逐项核对后）`）
- 上游：`7c705a7`（评估原型初版）→ `18b839d`（文档清理）→ **`03f90e9`（本报告对应的改动）**
- 性质：对逐项核对意见的逐条核实与修正记录；所有结论均为**实测**，原型局限已标注

---

## 一、这份报告讲什么

上一轮交付了任务对齐评估原型（分诊评估 + 检测探针），并在 `EVAL_PROTOTYPE_REPORT.md` 中报告了结果。随后对方逐项核对脚本、产物、统计数字和覆盖范围，提出 6 处需要修正的问题。

**本报告只讲这一轮修正**：每条意见是否成立、核实依据是什么、改了什么、对结论有什么影响。原型的整体背景与设计仍见 `EVAL_PROTOTYPE_REPORT.md`，这里不重复。

**核心结论先行**：6 条意见经核实**全部成立**，已全部修正。其中第 4 条（提示泄漏）的对照实验还额外挖出一个比原报告更弱的实测结论——原报告的"0 误报"至少部分是 fixture 声明提示出来的，不是模型自身的干净检测能力。净效果是：**证明力比上一版更弱，但更诚实**。

---

## 二、改了哪些文件

| 文件 | 改动性质 |
|---|---|
| `scripts/evaluate_triage.py` | 指标改名 + McNemar 降级为描述性计数（+24 行净）|
| `scripts/evaluate_detection_probe.py` | 新增提示剥离对照 + token 真相披露（重写，+108/-69 行区间内）|
| `tests/test_evaluate_triage.py` | 断言从 `mcnemar_exact_p` 改为 `discordance` |
| `tests/test_evaluate_detection_probe.py` | 新增提示剥离单测；限定 synthetic 防线表述 |
| `EVAL_PROTOTYPE_REPORT.md` | 同步 6 处口径 + 新增第六节修正记录 |

提交统计：**5 files changed, 160 insertions(+), 69 deletions(-)**。生产代码、正式 curation、模型**全部未动**；未训练。

---

## 三、6 处修正逐条核实

### 1. 提交号含混 — 成立

**意见**：报告页首写 `7c705a7`，但报告文件本身是在 `18b839d` 提交的。

**核实**：`git log --diff-filter=A` 确认——脚本/测试初版在 `7c705a7`，文档清理与报告在 `18b839d`。

**修正**：页首改为明确区分三个提交（脚本初版 / 文档 / 本次修正），本报告再补上 `03f90e9`。

---

### 2. `json_format_success` 名不副实 — 成立

**意见**：该字段只判断 `len(verdicts) == len(records)`；生产 `explain_issues()` 会自愈缺失条目，因此它只能表示"返回结果完整"，不能证明原始 JSON 格式成功。

**核实**：读 `localguard/model.py` 第 680-715 行，确认生产 triage 循环对缺失 ID 会补占位条目（`模型未提供说明，请依据下方证据人工判断`），且非法 verdict 会被逐项剥离后重新校验。所以 verdicts 凑齐 ≠ 原始 JSON 干净解析；真正的解析失败会记在 audit log 的 `model_explanation_json_error` 事件里。

**修正**：
- 字段改名 `json_format_success` → `result_completeness`（产物中旧字段已确认不存在）
- 报告内嵌 `metric_notes` 说明其真实含义与局限
- 报告正文同步改写指标名与脚注

---

### 3. McNemar 用错场景 — 成立

**意见**：McNemar 用于两个模型/两种条件的配对二分类结果；这里比较的是单模型预测 vs 固定标签，算术正确但没有模型比较意义。

**核实**：样本全为 `likely_true` 标签，故 c（标签假判真）**结构性地恒为 0**，b=1、p=1.0 是必然结果，不携带信息量。同意这不是 McNemar 的适用场景。

**修正**：
- `summarise()` 输出从 `mcnemar_b/mcnemar_c/mcnemar_exact_p` 改为描述性 `discordance: {rejected_true, false_alarm}`
- `mcnemar_exact()` 纯函数保留（数学实现本身正确），但 docstring 明确"本原型不将其作为正式检验"及原因
- 测试断言同步：验证 `discordance == {'rejected_true': 1, 'false_alarm': 0}` 且 `mcnemar_exact_p` 不再出现在输出中
- 报告删除"McNemar p=1.0"作为结论的表述

---

### 4. detection probe 提示泄漏 — 成立，且对照实验有新发现

**意见**：样本首行 `STATIC FIXTURE ONLY. Never import or execute.` 会提示模型直接判安全，0 误报不能推广；应增加去除提示后的对照探针。

**核实与修正**：
- 一处措辞更正：脚本读的是记录**全部** `result.lines`，并非"前 8 行"——只是这批样本本身恰好各只有 8 行。结论（首行提示存在）不受影响，已在报告中如实说明。
- 除首行 fixture 声明外，还发现第 6/8 行等安全解释注释（`# User text is HTML-escaped`、`// html/template auto-escapes`、`// User content is escaped before insertion`），构成双重提示泄漏。
- 新增 `is_hint_comment()` / `sample_text(strip_hints=True)`，剥离声明性注释但保留真实代码行。
- `run()` 改为跑两组：`with_hints`（原样）+ `hint_stripped`（剥离提示），各自统计误报。

**实测对照结果**（`.workbuddy/detection_probe.json`）：

| 指标 | with_hints（原样）| hint_stripped（剥离提示）|
|---|---|---|
| 样本数 | 11 | 11 |
| 有效 JSON | 11 / 11 | 11 / 11 |
| 误报数 | 0 | **1**（`clean-pilot-hash_verified`）|
| 误报率 | 0.0 | **0.0909** |

**新发现（实测）**：剥掉 fixture 声明后，`clean-pilot-hash_verified` 从"无误报"翻转为"报问题"。剥离后送模型的文本只剩 `verify_digest()` 函数头与 `sha256().hexdigest()` ——该静态夹具本身被截断（看不到 `hmac.compare_digest` 的返回值行），模型据不完整代码报了问题。这说明**原报告的 0 误报至少部分是 fixture 声明提示出来的**，不能作为一般安全代码检测能力的证据。

**边界**：hint_stripped 的 1/11 同样不是真实误报率——样本是人为截断的静态夹具，不是生产代码。两组都是检测任务，都不能证明分诊质量。

---

### 5. "永远不会被误并入训练集"过强 — 成立

**意见**：准确表述应是"当前 `validate_record()` 会拒绝带 `synthetic=true` 的记录"。

**核实**：`validate_record` 确实拒绝 synthetic 记录（报 "Synthetic/test fixtures cannot be promoted to real training samples"），但这是现版校验器行为，不是不可绕过的设计保证——删除标记或改动校验逻辑即可突破。

**修正**：报告改为限定表述，并在单测注释中写明"property of today's validator, not an immutable guarantee"。

---

### 6. 推理路径披露不完整 — 成立，且发现更深的问题

**意见**：检测探针用 `max_tokens=256`，`evaluate_holdout.py` 用 `max_new_tokens=192`，报告应披露 token 上限差异。

**核实**：读 `localguard/model.py` 的 `_infer()` 实现（第 298-310 行）发现——`structured=False` 时，`max_tokens` 参数**根本不进入 payload**，payload 里硬编码 `max_tokens=512`。所以初版传的 256 是**无效参数**，实际生效值是 512。真实差异比意见指出的更大：**512（HTTP）vs 192（transformers）**，不是 256 vs 192。

**修正**：
- 删除无效的 `max_tokens=256` 实参，并在代码注释中说明 `_infer` 的非 structured 分支忽略该参数
- 报告 `path_disclosure` 如实写明：同一权重/temperature=0/`enable_thinking=False`，但 token 上限 512 vs 192，不做"路径等价"声明

---

## 四、验证

- **全套测试 409 passed, 86 subtests passed**（原有 403 + 原型初版 5 + 本次新增 1）。必须用项目虚拟环境 `.venv/Scripts/python.exe`；系统 Python 缺 `tree-sitter-language-pack`，会得到 343 passed / 65 failed 的假象（核对方已复现并排除，报告已注明此坑）。
- **单测覆盖**：6 个针对性测试（统计函数 3 + synthetic 防线/样本构造/提示剥离 3）全部通过。
- **范围纪律**：`git diff HEAD -- localguard/ .localguard/curation/` 为空——生产代码与正式数据未动。
- **双端同步**：GitCode 正常推送（`18b839d..03f90e9`）；GitHub 因历史分叉用 contents API 兜底同步 5 个文件，逐个 sha256 与本地一致（FAIL=0）。工作区干净。

---

## 五、净结论

作为 **smoke test**，原型仍然合格：范围克制、产物可复核、不宣称模型质量。本次修正后：

- **统计口径更准确**：不再把返回完整性叫成 JSON 成功率，不再把无意义的 p=1.0 冒充检验。
- **检测结论更弱但更诚实**：0 误报被对照实验证伪为"部分由提示造成"，且如实披露 token 路径差异。
- **防线表述更严谨**：synthetic 隔离是现版校验器行为，不是永久保证。

**不变的下游边界**：真正回答"当前模型分诊误报高不高"仍需人工金标集，尤其是"扫描器确实命中但实际安全"的难负例。在此之前不做 prompt A/B、不扩正样本、不重训。
