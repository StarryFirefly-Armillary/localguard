# 训练燃料建议评估与决策

- 日期：2026-11-24
- 输入：`MODEL_TRAINING_FUEL_RECOMMENDATIONS.md`（另一 AI 的建议报告）
- 结论：**核心判断全部采纳，立即执行阶段 A 的第一步（任务对齐评估）**
- 性质：本文件是决策记录；具体代码改动待用户授权后执行

---

## 一、对建议的核实结果

我逐条核实了建议的关键指控，**全部属实**：

| 建议指控 | 核实结果 |
|---|---|
| 上轮门控只有 1 条样本变化 | ✅ 属实：逐样本对比 before/after，只有 `safe-CVE-2021-44906-dialogue` 从 True→False；McNemar b=1/c=0，p=1.0；FPR 区间 11.8–76.9% vs 3.6–62.4% 高度重叠 |
| held-out 不是 7 个独立样本 | ✅ 属实：正样本 2 条均来自 minimist 同一函数家族，vulnerable/safe 配对共享代码结构 |
| 评估任务与生产任务错配 | ✅ 属实且是关键：`evaluate_holdout.py` 提示要求"从原始代码输出 issues"（空数组=无漏洞）；生产 `explain_issues` 是"对已验证 finding 输出 verdict"。两者不是同一任务 |
| 11 条试点不是分诊负样本 | ✅ 属实：它们的训练目标是空 issues，不是"已命中发现但应判 likely_false" |
| `max_negative_ratio` 不是记录比例 | ✅ 属实：`training.py` 只把 clean_evidence 算负样本；"18 正/34 负"只是行数比，不是 turn 级配比 |
| reviews 未进训练链路 | ✅ 属实：`ingest_logs()` 只读 logs 表；reviews 表 2 条反馈没被消费 |

**这份建议的质量很高**，尤其"任务错配"是我之前分析报告里的真实盲点——我一直讨论"加多少数据"，却没发现评估本身测的是另一个任务。

---

## 二、决策

### 2.1 采纳的核心判断

1. **不重训、不部署新模型**（与建议一致）
2. **当前最缺的不是更多训练文本，而是任务对齐的评估数据 + 复核回流**——采纳建议第七节的表述，替代我原来的"缺燃料"说法
3. **11 条试点样本降级为 probe 集**，不并入训练集；保留 synthetic 标记
4. **评估口径修正**：没有实际 verdict 时不能标记分诊完成；`triaged_count/total` 必须可见

### 2.2 立即执行（本次授权后动手，低成本、可验证）

**第一步：任务对齐评估流水线原型 `scripts/evaluate_triage.py`（smoke test，不是质量评估）**

理由：`tool_call.jsonl` 的记录已含已验证 finding（issues 带 locations/snippet_hash + view_file 证据）——这是生产分诊的真实输入形态，可以作为**原型**样本，无需重新标注。

设计：
- 输入：已验证 finding（title/severity/category/cwe/evidence 片段/locations）+ 标签
- 提示：与生产 `explain_issues` 的 triage 分支一致（verdict + confidence + reason，不重新发现漏洞）
- **复用完整推理路径，而非只复制 system prompt**：固定 JSON schema、`batch_size`(=4 for triage)、`max_tokens`(=2048)、解析/异常降级逻辑、模型版本与量化(Q4_K_M)、推理参数(`temperature=0`、`enable_thinking=false`)。否则结果不代表线上分诊。
- 输出：per-sample verdict、McNemar 精确检验、Wilson CI、`triaged_count/total`、JSON 格式成功率
- 规模：先用 `tool_call.jsonl` 的 6 条 + 2 条 reviews 能关联的 finding 约 8 条
- **口径限定（重要）**：这是**评估流水线原型 / smoke test**。8 条样本上的 McNemar/Wilson 只用于验证**计算与输出格式正确**，**不产出模型优劣结论**。正样本仍集中同一 CVE/函数家族，缺人工确认正样本与 uncertain 样本，不足以覆盖不同规则/语言/误报类型。
- 不做：不改生产提示、不改模型、不改训练数据

**第二步：11 条试点改标 detection probe（不是 triage probe）**

修正（采纳第三方评价）：这 11 条是 `clean_evidence`、`issues` 全空——**扫描器没有产生 finding**。而生产 triage 的输入是"已被报告、等待判断真假的 finding"。用 triage 提示跑它们没有 finding 可分诊，测的其实是"模型会不会无中生有发现问题"，即**检测评估**。

- 在 `pilot_clean_evidence.jsonl` 的记录里加 `role: "detection_probe"` 与 `synthetic: true` 标记（不动正式 curation）
- 写一个 probe 脚本，用**检测提示**（`evaluate_holdout.py` 那套：从原始代码输出 issues，空数组=无漏洞）跑这 11 条，测"安全代码是否被误报为问题"
- **分诊 probe 另建**：必须来自真实或人工构造的"扫描命中但实际安全"的 finding（即带 issues 且人工标为 false_positive），不能用零发现样本代替

### 2.3 暂缓执行（需先有数据）

- 阶段 B 的 prompt A/B：需要先有任务对齐评估集（第一步产物）才有意义
- 阶段 C 扩训练燃料：正样本扩容（security_dialogue / cve_patch）与 reviewed_finding 导出，是独立的数据工程项目，建议单独立项
- 阶段 D 重训门禁：建议的 100 正/200 负/20 家族门槛合理，但以当前数据规模需长期积累，不是近期目标

### 2.4 我保留的一个不同意见

建议里"后续训练默认 1:1"——我同意作为起点，但要注意：`max_negative_ratio` 只数 clean_evidence，而 `security_dialogue` 的 safe implementation 虽含负样本语义却算正样本。所以**改比例之前先修计数口径**（建议 2.5 节也指出了这点），否则 1:1 是假的 1:1。

---

## 三、对第三方评价的采纳记录

用户转来的独立评价指出三处问题，我全部采纳并已修正上文：

| 评价意见 | 是否成立 | 修正 |
|---|---|---|
| 11 条 probe 仍有任务错配：它们是零 finding 的 clean_evidence，用 triage 提示测的是"检测"不是"分诊" | ✅ 成立（已核实 11 条 `issues` 全空）| 第二步改为 **detection probe**（用检测提示）；分诊 probe 另建，必须来自"扫描命中但实际安全"的 finding |
| "无需重新标注"只够原型：约 8 条、同一 CVE 家族，McNemar/Wilson 在 8 条上只能验证计算 | ✅ 成立 | 第一步明确定位为**评估流水线原型/smoke test**，明确"不产出模型优劣结论" |
| 复用生产提示要复用完整推理路径，不能只复制 system prompt | ✅ 成立 | 第一步加入固定项清单：schema / batch_size / max_tokens / 解析降级 / 模型版本与量化 / 推理参数 |

评价的"最终判断"——方向正确、可批准执行、但不扩大 Scope、后续需**小型人工金标集（含扫描器确实误报的难负例）**——与我的决策一致。金标集是进入重训决策前的硬前提，列入 2.3 暂缓项。

---

## 四、执行前提

第一步（任务对齐评估脚本原型）是只读消费现有 artifact + 新增一个评估脚本，**不需要 GPU、不需要腾空显存、不改生产代码**。如果用户授权，我可以直接开始。

涉及的人工标注扩展（阶段 C）和重训（阶段 D）不在此次执行范围。
