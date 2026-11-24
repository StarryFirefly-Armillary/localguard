# LocalGuard 任务对齐评估原型执行报告

- 日期：2026-11-24
- 提交：脚本与测试初版 `7c705a7`；文档清理与本报告 `18b839d`；口径修正与提示泄漏对照见最新提交（本报告已按修正后的实现更新）
- 性质：**评估工具原型 / smoke test**，不是模型质量评估，不产出重训或部署结论
- 版本说明：本报告经逐项核对后修订，修正内容见第六节；所有数字均为实测，原型推断已明确标注

---

## 一、背景：为什么要做这件事

前几轮对"训练燃料不足"的分析暴露出一个**根本性问题**：现有评估在测错误的任务。

- 生产分诊（`explain_issues`, `triage=True`）做的是：对扫描器**已发现的 finding** 判 `likely_true` / `likely_false` / `uncertain`。
- 而旧的 `evaluate_holdout.py` 测的是：模型能否**从原始代码里发现漏洞**（输出 `{"issues":[...]}`）。

两者是完全不同的任务，"加训练数据"改善不了评估错配。因此决策是：**暂停重训、先修评估任务、打通复核回流**；本次只执行第一步——一个只读、不需要 GPU（复用已启动的推理端点）、不动生产代码的评估原型。

第三方评价进一步收紧了三条，全部采纳：

1. 11 条试点是零 finding 的 `clean_evidence`，只能做 **detection probe**，不能冒充分诊负样本；
2. 6–8 条样本上的 McNemar / Wilson CI 只验证**计算与输出格式**，不能下模型优劣结论；
3. 复用生产提示要复用**完整推理路径**（schema、batch、max_tokens、解析降级、模型版本与量化、推理参数），不只是复制 system prompt。

---

## 二、交付物

| 文件 | 作用 |
|---|---|
| `scripts/evaluate_triage.py` | 任务对齐的分诊评估原型 |
| `scripts/evaluate_detection_probe.py` | 11 条合成干净样本的检测探针（含提示剥离对照）|
| `tests/test_evaluate_triage.py` | 锁定统计函数与不一致计数方向 |
| `tests/test_evaluate_detection_probe.py` | 锁定 synthetic 防线、样本构造与提示剥离 |
| `.workbuddy/pilot_clean/pilot_clean_evidence.jsonl` | 11 条试点加 `role=detection_probe` + `synthetic=true` 标记（本地数据，gitignore）|

---

## 三、分诊评估原型 `evaluate_triage.py`

**设计要点**

- **直接调用生产方法** `model.explain_issues(records, '8gb', triage=True)`，不复制其逻辑。system prompt、JSON schema、batch_size=4、max_tokens=2048、解析/异常降级、模型版本与 Q4_K_M 量化、temperature=0 / thinking off 全部天然一致——这是满足"复用完整推理路径"最可靠的方式，杜绝复制后漂移。
- 输入：`tool_call.jsonl` 的 6 条已验证 finding（issues 带 locations/snippet_hash + view_file 证据），转换成生产 `contexts` 形态（id/title/severity/category/cwe/language/origin_hint/source）。
- 标签：这 6 条是真实 CVE 的 pre-fix 代码，对分诊而言 ground truth 记为 `likely_true` 候选。
- 输出：per-sample verdict、Wilson 95% CI、`triaged_count/total`、`result_completeness`、描述性不一致计数。统计函数做成纯函数便于单测。
- 报告内嵌 warning：`SMOKE TEST ONLY`，明确禁止用于重训/部署决策。
- **口径修正（见第六节）**：初版把两个指标叫错了——`json_format_success` 实为返回条数完整性（生产 `explain_issues` 会为缺失 ID 补占位条目，不能证明原始 JSON 解析成功），已改名 `result_completeness`；McNemar 精确检验在"单模型 + 全正标签"下 c 结构性地为 0、p 恒为 1.0，没有配对比较意义，已降级为描述性 `discordance` 计数（纯函数保留但不再作为检验呈现）。

**实测结果**（产物在 `.workbuddy/triage_eval_prototype.json`）

| 指标 | 值 |
|---|---|
| 样本数 / 覆盖 | 6 / 6（coverage 1.0）|
| verdict 分布 | 5 `likely_true`，1 `likely_false`（CVE-2022-30123），0 `uncertain` |
| 点估计 accuracy | 0.8333（5/6）|
| Wilson 95% CI | **[0.4365, 0.9699]**——极宽 |
| 描述性不一致 | `rejected_true`=1, `false_alarm`=0（非 McNemar 检验）|
| `result_completeness` | True（仅表示 6 个 ID 都有返回，不代表原始 JSON 干净解析）|

这组数字自己印证了结论：区间宽到几乎覆盖全程，**6 条样本不具备任何统计结论力**。

**过程中修复的真实 bug**：初版把 curation 原始记录 ID（如 `CVE-2022-29217-tool_call`）传给 verdicts 查找，而 verdicts 的 key 是 issue id（`ISSUE-e787...`），ID 空间不匹配导致统计全 0。改为传与 verdicts 同 ID 空间的 records 后正确。另修正了不一致计数方向（b=标签真判假/拒真，c=标签假判真/误报）。

---

## 四、检测探针 `evaluate_detection_probe.py`

**设计要点**

- 复用 `evaluate_holdout.SYSTEM`（**import 而非复制**，保证提示一致），走已启动的 llama-server（端口 17865）HTTP 端点；通过 `model._infer(..., structured=False)` 对齐基线（非 structured，提示约束方式一致，**但 token 预算有差异，见下**）。
- 对 11 条 `pilot_clean` 合成干净代码跑**检测任务**，统计"误报数"（有 issues 的条数）。
- **提示泄漏对照**：样本含 `# STATIC FIXTURE ONLY. Never import or execute.` 及安全解释注释（如 `HTML-escaped`、`auto-escapes`、`never innerHTML`）。这些声明可能直接引导模型输出"无问题"。因此跑两组：原样（with_hints）+ 剥离声明性注释（hint_stripped），后者是混淆因素对照。

**推理路径披露**：两条路径都是同一 Q4_K_M 权重、temperature=0、`enable_thinking=False`，但 token 上限**不同**——本探针走 HTTP，`_infer(structured=False)` 在 payload 中**硬编码 `max_tokens=512`**（初版传的 `max_tokens=256` 参数被忽略、已删除）；`evaluate_holdout.py` 走 transformers，`max_new_tokens=192`。差异如实记录，不做"路径等价"声明。

**实测结果**（`.workbuddy/detection_probe.json`）

| 指标 | with_hints（原样）| hint_stripped（剥离提示）|
|---|---|---|
| 样本数 | 11 | 11 |
| 有效 JSON | 11 / 11 | 11 / 11 |
| 误报数 | 0 | **1**（`clean-pilot-hash_verified`）|
| 误报率 | 0.0 | **0.0909** |

**关键发现（实测，证实提示泄漏）**：剥掉 fixture 声明后，`clean-pilot-hash_verified` 从"无误报"翻转为"报问题"——剥离后送模型的文本只剩 `verify_digest()` 函数头与 `sha256().hexdigest()`（该静态夹具本身被截断，看不到 `hmac.compare_digest` 返回值行），模型据不完整代码报了问题。这证明 **0 误报至少部分是 fixture 声明提示出来的，不能推广到一般安全代码**。

**重要边界**：两组都是**检测任务**，只说明模型在这批截断的静态夹具上是否"无中生有"，**不能证明分诊质量**。hint_stripped 的 1/11 也不是真实误报率——样本是人为截断的夹具，不是生产代码。

**反投毒防线（限定表述）**：给试点记录加 `synthetic=true` 后，**当前**训练校验器 `validate_record` 拒绝其晋升为训练样本（"Synthetic/test fixtures cannot be promoted to real training samples"）。这是现版校验器的行为，不是不可绕过的设计保证——若删除标记或改动校验逻辑，防线仍可能被突破。标记予以保留。

---

## 五、验证与范围纪律

- **全套测试 409 passed, 86 subtests passed**（原有 403 + 初版 5 + 本次提示剥离新增 1）。注意：必须用项目虚拟环境 `.venv/Scripts/python.exe` 跑；系统 Python 缺 `tree-sitter-language-pack`，会得到 343 passed / 65 failed 的假象（用户核对时已复现并排除）。
- **范围纪律**：生产代码、正式 curation、模型**全部未动**；未训练；未改对外评估口径声明。工作区改动仅为 2 个脚本 + 2 个测试 + 文档；`.workbuddy/` 下的探针数据被 gitignore。
- **双端同步**：GitCode 正常推送；GitHub 因历史 API 兜底造成的分叉，普通 push 被拒，按工程约定用 contents API 兜底，逐字节 sha256 核实一致。

---

## 六、逐项核对后的修正记录

报告初稿经逐项核对，6 处口径问题全部成立并已修正：

| # | 问题 | 修正 |
|---|---|---|
| 1 | 提交号含混（写 `7c705a7`，报告实为 `18b839d`）| 页首改为区分脚本初版/文档/本次修正三个提交 |
| 2 | `json_format_success` 名不副实（`explain_issues` 自愈缺失 ID）| 改名 `result_completeness`，注明只测返回条数、不证明原始 JSON 解析成功 |
| 3 | McNemar 用错场景（单模型 vs 固定标签，非配对比较）| 降级为描述性 `discordance` 计数，移除 p 值呈现；纯函数保留并加语义注释 |
| 4 | detection probe 提示泄漏（`STATIC FIXTURE ONLY` + 安全注释）| **新增 hint_stripped 对照探针并实跑**，发现 0→1 误报翻转，如实披露；注明"前 8 行"措辞不准——脚本读全部行，样本本身仅 8 行 |
| 5 | "永远不会被误并入训练集"过强 | 改为"当前 `validate_record()` 会拒绝"，注明非不可绕过保证 |
| 6 | 推理路径披露不完整 | 披露 token 差异，并纠正：HTTP 路径实际 `max_tokens=512`（原 256 参数被 `_infer` 忽略），transformers 为 192 |

**净结论不变**：作为 smoke test 合格——范围克制、产物可复核、不宣称模型质量。修正后证明力更弱（detection 0 误报被证伪为部分提示所致），但更诚实。

---

## 七、下一步的自然边界（本次未做）

这个原型只证明"评估管线算得对"。要真正回答"当前模型分诊误报高不高"，还缺第三方评价强调的**小型人工金标集**，尤其是：

- "扫描器确实命中但实际安全"的**难负例**（现有数据几乎没有——零发现干净代码无法替代）；
- 人工确认的正样本与 `uncertain` 样本；
- 覆盖不同规则、语言、误报类型的样本。

这属于阶段 C 的数据工程，不在此次执行范围。在此之前，不做 prompt A/B、不扩正样本、不重训。

---

## 附：本次清理

删除了 4 份已完成使命的过程性文档（均已在 git 历史中，可随时恢复）：
`MODEL_TRAINING_FUEL_ANALYSIS.md`、`MODEL_TRAINING_FUEL_RECOMMENDATIONS.md`、`FUEL_RECOMMENDATIONS_DECISION.md`、`OPTIMIZATION_FIX_REPORT.md`。
项目长期文档（`README.md`、`DECISIONS.md`、`SELF_AUDIT_REPORT.md`、`PROJECT_OPTIMIZATION_REPORT.md`、`THIRD_PARTY_NOTICES.md`、`docs/`、`benchmarks/`）保留。
