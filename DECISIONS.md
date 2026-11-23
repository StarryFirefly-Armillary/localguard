# 自查报告决策 — 下一轮迭代

> 日期：2026-11-23 11:06
> 输入：`SELF_AUDIT_REPORT.md`（只读自查，9 条建议，附代码坐标）
> 性质：**决策文件**。本报告只定"做什么、不做什么、为什么"，实施另起；沿用工程约定每次迭代后同步 GitHub。

---

## 决策总览

| 条目 | 报告优先级 | 我的决策 | 理由 |
|---|---|---|---|
| 报告校验失败清空整份报告 | P0 | **立即做（方案 A+）** | 唯一会造成实质结果丢失，直接违背「不删发现」核心纪律 |
| README / STATUS 文档脱节 | P1 | **同批做** | 零代码风险，且含合规措辞（Semgrep Rules License 禁止再分发） |
| `clone_repository` MCP 无确认 | P1 | **改文档，不加代码** | 加确认 token 会破坏 MCP 自动化；白名单+隔离已收敛风险，问题是声明不一致 |
| 测试调用 venv `.exe` launcher | P2 | **做** | 迁移后已实际引发 4 个测试失败，改用 `python -m` 消除路径耦合 |
| CI semgrep 不锁版本 | P2 | **做** | 召回门禁是基准，上游漂移会让它失效，锁 `1.186.0` |
| `--ignore=tests/test_engine.py` 残留 | P2 | **做** | 文件从未存在，纯清理 |
| 31 个 launcher 旧 shebang | P2 | **暂缓，记录** | 现有工作流全用 `python -m`，不阻塞；逐包重装收益低、部分包无本地 wheel |
| `vram_mb` 未使用 | P2 | **暂缓，转产品决策** | 这是"要不要做显存调度"的产品题，不是 bug；不在本轮擅自删 schema |
| 阈值/常量重复不一致 | P2 | **做（低风险部分）** | 统一 `SEVERITIES` 定义；max_file_bytes 等阈值差异需评估行为影响，另议 |
| baseline 异常静默吞掉 | P3 | **做** | STATUS.md:184 已有同类教训，至少记 warning |
| 达上限丢发现无计数 | P3 | **做** | 加 `dropped_count`，机器可读，零行为改变 |
| 死代码 `discovery.scan()` | P3 | **做** | 零引用，安全删除 |

报告"已核实完整、无需改动"的 7 项能力（SARIF / analyze_image / queue_position / keep_model_resident / stale hash / 4gb 档 / MCP 审计日志）**不动**；排除的 2 项误报（严重度合并方向、任务书能力缺失）**不复议**。

---

## P0 详细决策：报告校验失败不清空

报告建议 A「局部剔除」，我采用 **A+**，因为发现两类失败必须区别对待：

### 失败分类（关键）

1. **单条 issue 位置无效** — `publish_report` 中 `reject()` 的三类：
   - 位置无快照证据（无 `snapshot_hashes` 条目）
   - 同一文件内行距 ≥ 400（超可读范围）
   - `view_file` 读取失败
   → **剔除该条**，写 `location_rejected` 日志 + result warning，保留其余已校验 issue。

2. **快照全局失效** — 源码在扫描后或报告校验期间被改动（`read['hash'] != snapshot_hashes` 或结尾 `checked_paths` 复查失败）：
   → 这是"整个审查基于过期快照"，不能伪装成部分成功。标记 `status='failed'`，但**保留已通过校验的 issues**（方案 B 的现场保留），让用户看到发生了什么。

### 具体改动

- `registry.publish_report`（`registry.py:279-310`）：把 `reject()` 从"抛异常"改为对单条失败记日志 + `continue` 到下一条；对快照失效类返回结构化错误标记而非清空。
- `engine.py:400-406` 的 `finally`：`except` 分支不再 `issues=[]`，改为保留 `result['issues']`（已校验部分）+ 明确 error 说明。
- **测试**：补 engine 层测试锁定"单条位置失败不导致全量清空"；保留底层 `EvidenceError` 测试（`tests/test_report_integrity.py:66`）不动——底层契约仍在，只是 engine 不再把它转成毁灭性结果。

### 底线

无论哪种失败：**不静默、不删有效发现、用户可见原因**。这条要写进测试断言。

---

## P1 clone_repository：为什么选"改文档"而非"加代码"

报告给了两个选项。我选后者（修正文档），理由：

- **风险已被技术收敛**：host 白名单双重校验、禁凭据/端口/query、禁 submodule/hook、`--depth 2`、目标隔离在 data_dir。唯一联网动作的开火面很小。
- **加确认 token 的代价**：MCP 的价值就是自动化编排。一次 tool call 弹一次确认，会让外部客户端的批量流程无法工作；且 token 机制本身要防重放、防绕过，复杂度远超问题本身。
- **问题本质是声明不一致**：文档说"must be user-confirmed"，实现是"UI 确认 + MCP 受约束不确认"。把文档改准确即可，同时保留白名单作为真实防线。

改动：`schemas.py:98` 的工具描述、`README.md` 对应段落，明确"UI 侧需用户确认；MCP 侧受白名单与隔离约束、不做交互确认"。

---

## P1 文档校准（含合规措辞）

三处一次性改：

- `README.md:5` —「135 条精选 Semgrep 规则」→「92 条 MIT 授权规则（VulnShop）」。**这条是合规必改**：受 Semgrep Rules License v1.0 约束的规则禁止再分发，旧措辞会重新引入许可风险。
- `README.md:34,130` —「345 测试 / 345 passed」→「368 passed」。
- `README.md:144` —「在 Actions 里手动触发」→「每周一 03:00 UTC 定时触发 + 手动可触发」。
- `docs/STATUS.md:129` —「grype 依赖 CVE 无有效输出、需重构未做」→ 更新为已实现（精确 pin 收集、manifest 行号、scratch requirements）。

---

## P2 执行清单

1. **测试解耦 launcher**：`tests/test_security_rules.py:66` 改为 `python -m semgrep` 或动态定位解释器，不再硬编码 `.venv/Scripts/semgrep.exe`。
2. **CI 锁版本**：`ci.yml:52` → `pip install semgrep==1.186.0`。
3. **清理残留参数**：所有 `--ignore=tests/test_engine.py` 移除（记忆里的测试命令同步更新）。
4. **统一 SEVERITIES**：`scanners.py:38` 改为引用 `reporting.py` 的定义，消除双定义漂移。
5. **baseline 记日志**：`engine.py:389-390` 的 `except Exception: pass` 改为 `self.store.log(event='baseline_failed', ...)`。
6. **dropped_count**：`scanners.py:68` 的 `findings.pop()` 循环计数，写入 `result['dropped_count']`。
7. **删死代码**：`discovery.py:94` 的 `scan()`。

**暂缓项**：31 个 launcher shebang（不阻塞，逐包重装成本高）、`vram_mb`（产品决策，另议）、阈值对齐（涉及行为变化，需单独立项评估）。

---

## 执行纪律

- 每项改动**先测后合**：全套测试 368 passed 是回归基线；基准召回 62.5% 不许退化。
- P0 改动涉及"删发现"红线，必须有测试锁定"单条失败不全量清空"。
- 每批完成后按工程约定同步 GitHub（含 GitCode，按 `PROJECT-STATUS.md` 的推送小节）。
- 本决策不修正报告"已核实完整"和"排除误报"章节的结论——那些是已验证的事实，改了反而是倒退。

---

## 不做的事（明确边界）

- 不因为报告提到就重写 SARIF / analyze_image / 分诊等已完整能力。
- 不在本轮引入新规则、不动召回路径（上次补规则负收益回退的教训）。
- 不擅自删除 schema 字段或改变产物格式（兼容性）。
- 不把 token、本机路径写进任何入库文件。
