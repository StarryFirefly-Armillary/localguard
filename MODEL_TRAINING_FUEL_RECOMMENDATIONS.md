# LocalGuard 模型训练“燃料不足”问题：可行建议报告

- 日期：2026-11-24
- 输入附件：[MODEL_TRAINING_FUEL_ANALYSIS.md](file:///E:/LocalMD/MODEL_TRAINING_FUEL_ANALYSIS.md)
- 审查范围：训练数据校验、held-out 评估、QLoRA 门控、生产分诊提示、人工复核回流
- 处理方式：只读核实源码与本地 artifact，未启动训练、模型或 UI 服务
- 文件改动：仅新增本报告

## 一、核心结论

**当前不建议为了“增加 11 条负样本”立即重训并部署。** 更合理的顺序是：

1. 先建立与生产任务一致的评估集：输入“已验证的扫描发现”，判断 `likely_true / likely_false / uncertain`。
2. 用配对统计方法确认基座、当前微调模型和提示词之间是否真有差异。
3. 将人工复核回流为任务对齐的标注数据，同时扩充真实正样本和真实难负样本。
4. 只有在独立评估集上证明收益，且召回、格式成功率和解释质量不退化，才重训、合并和部署。

附件所说的“燃料不足”部分成立，但当前更关键的问题不是样本总量，而是：

- **评估任务与生产任务不一致**；
- **7 条 held-out 不足以支持统计结论**；
- **试点干净样本不是“扫描命中但安全”的分诊负样本**；
- **人工复核尚未真正进入训练数据链路**。

## 二、客观复核结果

### 2.1 上次门控只有 1 条样本发生变化

当前门控产物 [gate-result.json](file:///E:/LocalAI/LocalGuard/evaluation/balanced-1to1/gate-result.json) 显示：

- 微调前：`tp=2, fp=2, tn=3, fn=0`，FPR=0.4；
- 微调后：`tp=2, fp=1, tn=4, fn=0`，FPR=0.2。

逐样本比较 [before.json](file:///E:/LocalAI/LocalGuard/evaluation/balanced-1to1/before.json) 和 [after.json](file:///E:/LocalAI/LocalGuard/evaluation/balanced-1to1/after.json) 后可以确认：7 条样本中只有 `safe-CVE-2021-44906-dialogue` 从误报变为正确拒绝，其余 6 条预测不变。

因此：

- 配对 McNemar 表中 `b=1, c=0`，双侧精确检验 `p=1.0`；
- 改善前 FPR 的 Wilson 95% 置信区间约为 **11.8%–76.9%**；
- 改善后 FPR 的 Wilson 95% 置信区间约为 **3.6%–62.4%**；
- 两个区间高度重叠，不能据此宣称微调显著降低了总体误报率。

当前门控 [training.py:525](file:///E:/LocalMD/localguard/training.py#L525) 只要求 FPR 点估计下降至少 0.001，并要求其他点估计不下降；它没有显著性、置信区间、独立样本单位或最小样本量约束。对于 7 条样本，这个门槛只能防止明显退化，不能证明真实收益。

### 2.2 held-out 不是 7 个独立样本

[heldout.jsonl](file:///E:/LocalAI/LocalGuard/data/heldout.jsonl) 中：

- 正样本只有 2 条，均来自 `minimist` 的同一函数家族；
- 负样本包含同一 CVE 的安全实现，以及与正样本高度相关的 clean/safe 对照；
- 训练集和测试集即使 ID 不同， vulnerable/safe 配对仍可能共享代码结构、变量名和修复模式。

所以有效独立单位更接近“CVE/仓库/函数家族”，而不是 7 行 JSONL。直接对 7 行做 bootstrap 只能表达这 7 条内部的不确定性，不能补足独立信息。

### 2.3 当前评估测的是“发现漏洞”，不是“分诊误报”

[evaluate_holdout.py:31](file:///E:/LocalMD/scripts/evaluate_holdout.py#L31) 的系统提示要求模型从原始代码中输出 `issues`，空数组表示没有漏洞；正样本来自 `tool_call`，负样本来自 clean fixture 和安全实现。

但生产分诊在 [model.py:634](file:///E:/LocalMD/localguard/model.py#L634) 中要求模型：

- 输入已经是扫描器验证过的 finding；
- 只输出解释、修复建议和 `likely_true / likely_false / uncertain`；
- 不重新发现漏洞，不产生可信位置。

这意味着当前 held-out 的 FPR 是“模型在原始代码上误报漏洞的比例”，而用户痛点是“模型把已验证发现误判为 likely_true 的比例”。两者不是同一个任务，现有门控不能直接证明分诊质量。

### 2.4 11 条试点样本不能直接替代分诊负样本

试点脚本 [collect_pilot.py](file:///E:/LocalMD/.workbuddy/bench_model/collect_pilot.py) 通过真实 `view_file` 和 patterns 零发现扫描生成了 `clean_evidence`。严格校验 [training.py:302](file:///E:/LocalMD/localguard/training.py#L302) 能证明：

- 文件和日志真实存在；
- 哈希、session、扫描 artifact 一致；
- 该次 patterns 扫描没有命中。

但它不能证明：

- 代码在语义上绝对安全；
- semgrep、gitleaks、依赖扫描或人工审查也不会发现问题；
- 样本适合训练“对已命中发现做 likely_false 分诊”。

这些样本的训练目标是空 `issues`，不是“扫描器已经报告了一个问题，但该问题是误报”。因此它们更适合做：

- 独立安全探针；
- prompt 回归集；
- 模型是否过度拒报的对照；

而不是立即作为正式分诊负样本。

### 2.5 当前比例控制不是记录比例

[training.py:592](file:///E:/LocalMD/localguard/training.py#L592) 的 `max_negative_ratio` 只把 `clean_evidence` 视为负样本，并按 assistant turn 计数；`security_dialogue` 即使包含 safe implementation，也仍按正样本处理。比例还依赖输入记录顺序。

因此“正 18 / 负 34 = 1.89:1”只是记录数比例，不等于实际监督 turn 比例。后续训练应输出明确的 turn 级配比和分层抽样 manifest，而不是只看 JSONL 行数。

## 三、对附件五个问题的直接回答

### 问题 1：7 条 held-out 有没有更可靠的统计方法？

**有，但不能把 7 条变成可靠总体估计。** 当前能做的是：

- 报告精确计数和逐样本变化；
- 对 discordant 样本做 McNemar 精确检验；
- 给出 Wilson 或 Clopper-Pearson 区间；
- 明确有效独立家族数。

真正可靠的做法是扩评估集，并按家族做 paired bootstrap。建议：

- 初始评估集约 30–50 个正例、100–200 个负例；
- 至少 20 个独立 CVE/仓库/函数家族；
- 正例覆盖主要语言、CWE 和扫描规则；
- 负例必须包含真实扫描误报，而不只是 clean 文件；
- 以家族为单位做 2000 次 paired bootstrap，报告 FPR、precision、recall 差值的 95% CI。

### 问题 2：11 条试点值不值得现在用？

**值得保留和评估，不值得现在直接并入正式训练集。**

建议先将它们放入独立 probe 集，测试当前模型是否会把这些安全模式误判为问题。后续如果纳入训练，必须：

- 明确标记为 LLM 生成的合成候选；
- 记录生成模型、提示、版本和人工审核结果；
- 与训练/测试集做 AST、n-gram、哈希和近重复去重；
- 先 split 再生成，避免测试集污染；
- 增加真实难负例作为对照，防止模型只学会“短代码=安全”。

如果只增加这 11 条就跑门控，结果仍无法可靠解释，因为评估集没有同步扩大。

### 问题 3：如何合法扩大正样本？

**可行，优先扩 `security_dialogue`，再扩 `cve_patch`。**

推荐顺序：

1. **官方公告锚定的 security_dialogue**：选择有明确 CVE/GHSA、修复 commit、CWE 和受影响代码的真实事件，复用 [curate_cve_data.py:136](file:///E:/LocalMD/scripts/curate_cve_data.py#L136) 的 API receipt、commit 校验和许可证快照逻辑。
2. **真实 CVE patch**：从 OSV/GHSA 等来源发现候选，但必须人工确认 advisory 与 fix commit 的直接关联；固定 commit，提取完整函数和未变对照函数，不能只截取一条 diff 行。
3. **工具调用正样本**：从真实审查会话导出已验证 finding、`view_file` 证据和 scanner 日志，补足生产形态的数据。

许可上必须分别确认源码许可和公告文本许可；GitHub license 字段只能作为线索，不能替代 pinned license 文本。

### 问题 4：人工反馈如何变成训练燃料？

当前 `reviews` 已记录人工决定，[storage.py:293](file:///E:/LocalMD/localguard/storage.py#L293) 也写了 `human_review` 日志，但 [training.py:439](file:///E:/LocalMD/localguard/training.py#L439) 的 `ingest_logs()` 只读取 `location_rejected` 等日志，没有消费 reviews，所以库里只有 2 条反馈也不会自动形成训练样本。

建议新增显式、可审计的反馈导出流程：

- 用户 opt-in 后，冻结导出当时的 finding、证据、模型 verdict、人工决定、reviewer、时间戳和 audit_id；
- `confirmed` 可作为“已命中且真实”的分诊正例；
- `false_positive` 应使用新的 `reviewed_finding` 来源，不能伪装成 patterns 零发现的 clean 样本；
- 导出前做哈希、去重、证据完整性和 session 校验；
- 保留人工覆盖模型判断的标记；
- 数据进入训练集前仍需审核和 split。

### 问题 5：“暂缓重训”有没有盲点？

**作为部署决策是对的，但不应理解为什么都不做。** 盲点有两个：

1. 低成本的 prompt/校准实验可以先做，不必等数据扩完；
2. 小型诊断训练不是完全没价值，但必须先有任务对齐的评估集，否则仍然无法判断收益。

附件关于“QLoRA 不直接提升推理速度”的判断基本正确：它不改变架构、参数量或量化计算量。它只可能通过减少 JSON 重试、缩短输出或改善路由间接提速，必须实测，不能作为重训的主要理由。

## 四、推荐方案

### 阶段 A：建立任务对齐评估集

**目标**：能回答“当前模型是否把安全发现误判为 likely_true”。

每个评估样本应包含：

- 原始 scanner finding；
- 规则 ID、标题、severity、confidence；
- 文件路径和精确行号；
- `view_file` 证据片段；
- 必要的上下文；
- 模型 verdict/confidence/reason；
- 人工标签和 adjudication 结果。

标签建议：

- `confirmed`：证据支持真实问题；
- `false_positive`：扫描命中但人工确认安全或规则误报；
- `uncertain`：证据不足，允许保留，不强迫二分类。

评估指标：

- 主指标：固定召回下的分诊 precision / FPR；
- 辅助指标：uncertain 比例、覆盖率、JSON 格式成功率；
- 置信度校准时增加 Brier score 或 ECE；
- 解释质量单独做盲评 rubric；
- `cwe_accuracy` 和 `exact_line_accuracy` 不作为 advisory 主门禁，因为发现、CWE 和位置应由确定性工具负责。

### 阶段 B：先做不重训的 A/B 实验

固定评估集、提示解析器和模型版本，比较：

1. 当前提示；
2. 保守提示：证据不足时默认 `uncertain`，只有明确证据才输出 `likely_true`；
3. 高置信阈值：只让 `likely_true` 且 confidence 超过阈值影响排序；
4. 可选的“分诊与解释分离”提示，减少一次输出过多字段导致的 JSON 退化。

记录：

- FPR、precision、recall；
- uncertain 比例；
- JSON 失败率；
- 每批 token、耗时和重试次数；
- 人工盲评解释质量。

如果保守提示已经显著降低误报且不过度拒报，就没有必要为了同样目标立即重训。

### 阶段 C：扩充训练燃料

目标不是盲目追求行数，而是增加**独立家族和任务对齐样本**：

- `security_dialogue`：优先扩充，成本最低，直接训练解释和修复；
- `reviewed_finding`：来自人工复核，直接训练分诊；
- `cve_patch`：逐步建立 50+ 高质量真实补丁；
- `clean_evidence`：保留作对照，但不要让它淹没分诊难负例；
- 合成候选：只能占辅助比例，必须标记和审核。

训练时建议：

- 按 assistant turn 输出实际正负比例；
- 默认从 1:1 开始，不使用历史 4:1；
- 使用分层、确定性抽样，避免输入顺序影响比例；
- 同一 CVE/仓库/函数家族及其 vulnerable/safe 配对必须同 split；
- 先 1 epoch、小步消融，确认无退化后再扩大。

### 阶段 D：满足条件后才重训

最低启动条件建议：

- 任务对齐 held-out 达到约 100 个正例、200 个负例，或置信区间已足够窄；
- 至少 20 个独立家族；
- 至少 100 条人工审核的任务对齐反馈，其中正负样本均有足够数量；
- 基座、当前模型和新候选在同一测试集上完成配对评估；
- 评估脚本能输出家族级 bootstrap 和逐样本差异。

部署门禁建议：

- FPR 改善的 95% CI 下界大于 0，或达到预先定义的实际收益阈值；
- recall 非劣于预设容差，例如下降不超过 5 个百分点；
- JSON 格式成功率不退化；
- uncertain 比例和解释盲评不出现不可接受退化；
- 至少 3 个训练 seed 的结果一致，或明确报告 seed 方差；
- 最终测试集从未用于 prompt 或阈值调参。

如果 FPR 改善区间跨零、recall 明显下降、格式失败上升，或连续两轮训练没有稳定收益，应停止调参，而不是继续加数据碰运气。

## 五、近期最值得做的低成本动作

1. **修正评估任务**：新增生产形态的 triage 评估脚本，输入已验证 finding，而不是原始代码检测。
2. **导出 2 条人工复核**：先打通 reviews → 冻结 artifact → 新 `reviewed_finding` 数据格式。
3. **建立 20–30 条人工标注 probe**：覆盖参数化 SQL、环境变量密钥、白名单路径、HTML 转义、安全 JSON、hmac 比较等安全模式。
4. **跑 prompt A/B**：当前提示 vs 保守提示，记录误报、uncertain、JSON 失败和耗时。
5. **将 11 条试点放入 probe**：验证它们是否暴露“安全代码被判 likely_true”的问题，但不立即用于训练。
6. **修正覆盖率口径**：报告 `triaged_count/total`，没有实际 verdict 时不能标记分诊完成。

## 六、明确不建议

- 不建议在 7 条 held-out 上继续用点估计决定模型发布。
- 不建议把 patterns 零发现直接解释为语义安全。
- 不建议把 LLM 生成的干净代码去掉 synthetic 标记后当作真实训练样本。
- 不建议把 `false_positive` 复核记录转换成“零发现 clean”目标。
- 不建议为了优化 advisory 模型而把 CWE/行号准确率当成主目标。
- 不建议在评估集未扩大前，用 11 条新增样本重训并部署。
- 不建议继续调 4:1 负样本比例；历史已出现过度拒报和行号能力退化。

## 七、最终判断

附件的基本判断——“数据少、门控弱、暂缓重训”——是合理的，但需要把问题重新表述为：

> 当前最缺的不是更多训练文本，而是与生产分诊任务一致、按独立家族划分、带人工标签的评估数据和复核回流数据。

在这些基础建立之前，增加训练数据很可能只是让模型更熟练地拟合现有 41 条样本，而无法证明它真的减少了用户看到的误报。先修评估口径和反馈闭环，再用真实数据训练，才是成本更低、结果更可验证的路线。
