# LocalGuard 自查报告 — 下一轮迭代建议

> 生成时间：2026-11-23 11:05
> 性质：**只读自查，未改动任何代码**。所有条目均附代码坐标，经独立核验（含排除 2 项调研误报）。
> 基准：原始任务书 `whatineed.md`；实现核对：当前代码实读；测试基线：`pytest` 368 passed。

---

## 一、结论摘要

| 优先级 | 条目 | 性质 | 影响 |
|---|---|---|---|
| **P0** | 报告校验失败清空整份报告 | 功能缺陷 | 违背核心纪律「不删发现」，用户可能看到 0 条结果 |
| **P1** | README / STATUS 文档与代码脱节 | 文档债 + 合规 | 误导用户；「Semgrep 规则」措辞触碰已修正的许可问题 |
| **P1** | `clone_repository` 的 MCP 侧无用户确认 | 声明/实现不一致 | 外部客户端可绕过确认触发唯一联网动作 |
| **P2** | 测试直接调用 venv 的 `.exe` launcher | 环境脆弱 | 迁移后已实际引发 4 个测试失败 |
| **P2** | CI 的 semgrep 不锁版本 | 可复现性 | 基准召回门禁随上游版本漂移 |
| **P2** | `resource_estimate.vram_mb` 未使用 | 半实现 | 显存调度诉求未落地，虚假承诺 |
| **P2** | 阈值/常量重复且不一致 | 维护债 | 配置与实际行为可能背离 |
| **P3** | baseline 异常被静默吞掉 | 健壮性 | 变更对比失效且无日志 |
| **P3** | 死代码 `discovery.scan()` | 清理 | 无功能影响 |

**已核实完整、无需改动**（避免误改）：SARIF 导出、analyze_image、queue_position、keep_model_resident、locations stale hash 校验、4gb 降级档、UI/MCP 共享同一 registry/校验层——任务书点名的能力均真实存在，不存在两套审查逻辑。

---

## 二、P0 — 报告校验失败会清空整份报告

**问题**：`localguard/engine.py:402-407` 的 `finally` 中调用 `registry.publish_report()`。该方法在任一条 issue 的 location 校验失败时抛 `EvidenceError`（`ValueError` 子类，`reporting.py:27`），被 `except (ValueError, OSError)` 捕获后执行：

```python
result.update(status='failed', issues=[], error='Report validation failed: ...')
```

**后果**：只要**任意一条**发现的 location 校验失败（例如审查过程中源码被改动导致 stale），整份报告的**所有发现被清空**。这直接违背项目最核心的设计纪律「不删发现、人工复核优先」，且用户从报告上看不到任何解释。

**测试盲区**：`tests/test_report_integrity.py:55-71` 只验证到 `publish_report` 抛 `EvidenceError` 为止，没有测试 engine 层把它转化为 `issues=[]` 的下游后果——底层行为有测，用户可见的破坏性结果无测。

**建议方案**（择一，推荐 A）：
- **A. 局部剔除**：`publish_report` 校验失败时不抛异常终止，而是跳过该条 issue、写入 `rejected` 日志与 warning，返回的 `issues` 保留其余已通过项；engine 层不再清空。
- **B. 保留失败现场**：即使整体标记 failed，也保留已通过校验的 issues 供用户查看，而不是 `[]`。

补一条 engine 层测试，锁定「单条校验失败不导致全量清空」。

---

## 三、P1 — 文档与代码严重脱节

| 位置 | 文档现状 | 代码实际 | 性质 |
|---|---|---|---|
| `README.md:5,34,130` | 「135 条精选 Semgrep 规则」「345 测试」 | 92 条 MIT VulnShop 规则；368 passed | 数字过期 + 合规措辞错误 |
| `README.md:144` | 「完整基准需…在 Actions 里手动触发」 | `ci.yml:7-9` 每周一 03:00 UTC 定时触发 | 描述过期 |
| `docs/STATUS.md:129` | 「grype 依赖 CVE 无有效输出、需重构未做」 | 已实现：`scanners.py:442` 精确 pin 收集、`:519` manifest 行号、`:809-811` scratch requirements | 限制已消除但文档未更新 |

**合规提示**：README 中「135 条 Semgrep 规则」的措辞需特别处理。11-21 的许可修正（`docs/STATUS.md:132-140`）已将受 Semgrep Rules License v1.0 约束的规则全部剔除，因为该许可禁止再分发；当前规则包仅 92 条 MIT 授权的 VulnShop 规则。保留旧措辞会重新引入合规风险。

**建议**：一次性校准上述三处，纯文档操作、零代码风险。

---

## 四、P1 — `clone_repository` 的 MCP 侧无用户确认

**问题**：`README.md` 与 `schemas.py:98` 均声明该工具「must be user-confirmed / 需用户显式确认」。实际确认只实现在 UI 层（`localguard/static/app.js:275-307` 的 `confirmClone` 弹窗）。MCP 调用路径 `localguard/registry.py:181-226` 直接执行 clone，**无任何确认步骤**——外部 MCP 客户端一个 tool call 即可触发这唯一的联网动作。

**缓解现状**（非严重漏洞）：host 白名单二次校验、禁止凭据/端口/query/fragment、`--depth 2`、禁 submodule/hook、克隆目标隔离在 data_dir。风险是「声明与实现不一致」，而非任意联网。

**建议**：择一——
- 在 MCP 路径加入一次性确认 token / 配置开关（如 `allow_unconfirmed_clone`）；
- 或修正文档，明确「UI 侧需用户确认；MCP 侧受白名单与隔离约束、不做交互确认」。

---

## 五、P2 — 环境与可复现性

1. **测试与 venv launcher 耦合**：`tests/test_security_rules.py:66` 直接定位 `.venv/Scripts/semgrep.exe`。2026-11-23 迁移后该 launcher 内嵌旧 C 盘 shebang，导致 4 个测试失败（已用 pip 重装修复）。建议测试改用 `python -m semgrep` 或动态定位解释器，消除路径耦合。
2. **CI semgrep 不锁版本**：`.github/workflows/ci.yml:52` 为 `pip install semgrep`（本地为 1.186.0）。上游升级可能改变规则行为，使 40% 召回门禁突然失效或误报。建议锁定 `semgrep==1.186.0`。
3. **`--ignore=tests/test_engine.py` 残留**：该文件在 `tests/` 中不存在，git 历史里也从未存在过。测试命令与记忆里都应移除该参数（无功能影响，属清理）。
4. **31 个 launcher 仍带旧 shebang**：`.venv/Scripts` 14 个、`app-env/Scripts` 17 个（含 `localguard.exe`/`uvicorn.exe`/`pip.exe`）。当前测试与服务均用 `python -m` 调用、不经过这些 `.exe`，故不阻塞；但将来直接执行会静默失败。彻底修需按 pip 重装法逐包重建（部分包无本地 wheel，注意版本一致）。

---

## 六、P2/P3 — 代码质量

| 条目 | 坐标 | 说明 | 建议 |
|---|---|---|---|
| `vram_mb` 未使用 | `schemas.py:93` 声明；`engine.py:44,211` 只读 `ram_mb` | 任务书 4–8GB 显存调度诉求未落地 | 接上 vram 调度，或从 schema 删除避免虚假承诺 |
| 阈值重复且不一致 | `config.py:17-19`（max_file_bytes 2M / max_output 200000）vs `scanners.py:23-27`（1M / 200*1024）；`SEVERITIES` 双定义于 `reporting.py:11` 与 `scanners.py:38` | 配置与实际行为可能背离 | 统一到 config，scanners 引用配置 |
| baseline 异常静默吞掉 | `engine.py:389-390` `except Exception: pass` | 变更对比失效且无日志（STATUS.md:184 已有同类教训） | 至少记 warning 日志 |
| 达上限丢发现无机器可读计数 | `scanners.py:68` `findings.pop()` 仅写 warning | 难核对覆盖率 | 在 result 中记 `dropped_count` |
| 死代码 | `discovery.py:94` `scan()` 定义后全项目零引用 | 无影响 | 删除 |

---

## 七、排除的误报（记录以免重复讨论）

- **`reporting.py:73-74` 严重度合并**：调研曾怀疑「悄悄上调严重度」。核实 `SEVERITIES = {critical:0, high:1, ...}`，条件 `<` 取的是**更严重**等级，方向正确，符合「不弱化发现」。**非缺陷。**
- **任务书 7 项能力缺失**：SARIF / analyze_image / queue_position / keep_model_resident / stale hash / 4gb 档 / MCP 审计日志全部真实实现（`reporting.py:161`、`model.py:656`、`engine.py:201`、`config.py:23`、`registry.py:256,134-139`）。**非缺陷。**

---

## 八、建议执行顺序

1. **P0**：修报告清空缺陷 + 补测试（唯一会造成实质结果丢失的问题）。
2. **P1**：校准三处文档（含合规措辞）——零风险，建议与 P0 同批做。
3. **P1**：`clone_repository` 确认机制（决定策略后再动，涉及协议声明）。
4. **P2**：CI 锁版本 + 测试解耦 launcher + 清理残留参数。
5. **P3**：代码质量清理，可零散进行。

> 本次仅出具报告，未修改任何代码或配置。待决策后按序实施；每次迭代后按工程约定同步 GitHub。
