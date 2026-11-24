# LocalGuard 任务对齐评估原型执行报告

- 日期：2026-11-24
- 提交：`7c705a7`（会话末尾将提交文档清理与新报告）
- 性质：**评估工具原型 / smoke test**，不是模型质量评估，不产出重训或部署结论

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
| `scripts/evaluate_triage.py`（163 行）| 任务对齐的分诊评估原型 |
| `scripts/evaluate_detection_probe.py`（102 行）| 11 条合成干净样本的检测探针 |
| `tests/test_evaluate_triage.py`（37 行）| 锁定统计函数与 McNemar b/c 方向 |
| `tests/test_evaluate_detection_probe.py`（29 行）| 锁定 synthetic 防线与样本构造 |
| `.workbuddy/pilot_clean/pilot_clean_evidence.jsonl` | 11 条试点加 `role=detection_probe` + `synthetic=true` 标记（本地数据，gitignore）|

---

## 三、分诊评估原型 `evaluate_triage.py`

**设计要点**

- **直接调用生产方法** `model.explain_issues(records, '8gb', triage=True)`，不复制其逻辑。system prompt、JSON schema、batch_size=4、max_tokens=2048、解析/异常降级、模型版本与 Q4_K_M 量化、temperature=0 / thinking off 全部天然一致——这是满足"复用完整推理路径"最可靠的方式，杜绝复制后漂移。
- 输入：`tool_call.jsonl` 的 6 条已验证 finding（issues 带 locations/snippet_hash + view_file 证据），转换成生产 `contexts` 形态（id/title/severity/category/cwe/language/origin_hint/source）。
- 标签：这 6 条是真实 CVE 的 pre-fix 代码，对分诊而言 ground truth 记为 `likely_true` 候选。
- 输出：per-sample verdict、McNemar 精确检验、Wilson 95% CI、`triaged_count/total`、JSON 格式成功率。统计函数做成纯函数便于单测。
- 报告内嵌 warning：`SMOKE TEST ONLY`，明确禁止用于重训/部署决策。

**实测结果**（`E:/LocalAI/LocalGuard/evaluation` 无关，产物在 `.workbuddy/triage_eval_prototype.json`）

| 指标 | 值 |
|---|---|
| 样本数 / 覆盖 | 6 / 6（coverage 1.0）|
| verdict 分布 | 5 `likely_true`，1 `likely_false`（CVE-2022-30123），0 `uncertain` |
| 点估计 accuracy | 0.8333（5/6）|
| Wilson 95% CI | **[0.4365, 0.9699]**——极宽 |
| McNemar | b=1, c=0, **p=1.0** |
| JSON 格式成功率 | True |

这组数字自己印证了结论：区间宽到几乎覆盖全程、McNemar p=1.0，**6 条样本不具备任何统计结论力**。

**过程中修复的真实 bug**：初版把 curation 原始记录 ID（如 `CVE-2022-29217-tool_call`）传给 verdicts 查找，而 verdicts 的 key 是 issue id（`ISSUE-e787...`），ID 空间不匹配导致统计全 0。改为传与 verdicts 同 ID 空间的 records 后正确。另修正了 McNemar b/c 方向（标准定义：b=标签真判假/拒真，c=标签假判真/误报）。

---

## 四、检测探针 `evaluate_detection_probe.py`

**设计要点**

- 复用 `evaluate_holdout.SYSTEM`（**import 而非复制**，保证提示一致），走已启动的 llama-server（端口 17865）HTTP 端点；通过 `model._infer(..., structured=False)` 对齐基线（非 structured，与 transformers 路径的提示约束方式一致，报告中标注这一差异）。
- 对 11 条 `pilot_clean` 合成干净代码跑**检测任务**，统计"误报数"（有 issues 的条数）。

**实测结果**（`.workbuddy/detection_probe.json`）

| 指标 | 值 |
|---|---|
| 样本数 | 11 |
| 有效 JSON | 11 / 11 |
| 误报数 | 0 |
| 误报率 | 0.0 |

**重要边界**：这是检测任务的结果，只说明当前模型在这批**合成**干净样本上不会"无中生有"找漏洞，**不能证明分诊质量**（模型不会把误报 finding 判为 likely_true）。

**意外收获（反投毒防线得到验证）**：给试点记录加 `synthetic=true` 后，训练校验器 `validate_record` 明确拒绝其晋升为训练样本（"Synthetic/test fixtures cannot be promoted to real training samples"）。这意味着这批探针数据永远不会被误并入训练集，符合评价"明确标记 synthetic"的意图，标记予以保留。

---

## 五、验证与范围纪律

- **全套测试 408 passed**（原有 403 + 新增 5）。
- **范围纪律**：生产代码、正式 curation、模型**全部未动**；未训练；未改对外评估口径声明。工作区改动仅为 2 个脚本 + 2 个测试 + 本次文档；`.workbuddy/` 下的探针数据被 gitignore。
- **双端同步**：GitCode 正常推送；GitHub 因历史 API 兜底造成的分叉，普通 push 被拒，按工程约定用 contents API 兜底，逐字节 sha256 核实一致。

---

## 六、下一步的自然边界（本次未做）

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
