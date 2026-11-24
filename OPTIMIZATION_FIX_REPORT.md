# LocalGuard 优化报告核实与修复报告

- 日期：2026-11-24
- 输入：`PROJECT_OPTIMIZATION_REPORT.md`（10 项建议，自述"未运行测试/服务/基准"）
- 处理方式：逐条核实源码与测试，只修确凿问题；每项先写回归测试复现，再改代码，最后验证
- 结论：10 项建议中 **5 项确凿为真实问题，已全部修复**；其余 5 项是架构级优化建议，不是已存在的缺陷，需真实数据支撑后单独立项
- 提交：`ddc6657`（双端同步完成）

---

## 一、核实结果总览

| # | 报告建议 | 核实结论 | 处理 |
|---|---|---|---|
| 1 | 模型辅助功能拖垮审查 | 确凿 | 已修复 |
| 2 | 自动排除与依赖扫描冲突 | 确凿 | 已修复 |
| 3 | 扫描缓存返回过期结果 | 确凿 | 已修复 |
| 4 | 实时日志游标饥饿 | 确凿 | 已修复 |
| 5 | 基准升级为质量门禁 | 合理建议，非 bug | 未纳入，见第五节 |
| 6 | 优化快照与重复 I/O | 合理建议，非 bug | 未纳入 |
| 7 | 发现截断偏向高风险 | 合理建议，非 bug | 未纳入 |
| 8 | 队列/数据库/前端规模化 | 合理建议，非 bug | 未纳入 |
| 9 | 模型评估更大样本 | 合理建议，非 bug | 未纳入 |
| 10 | 交付脚本与文档一致性 | 确凿 | 已修复 |

---

## 二、五项修复详情

### 修复 1：模型畸形响应不再拖垮整次审查

**定位**：`localguard/model.py` 的 `explain_warnings()`；`localguard/engine.py` 的 advisory 分支

**根因**：
- `explain_warnings()` 直接读取 `response['choices'][0]['message']['content']`
- 模型返回空 `choices`、缺 `message`、非 JSON 等畸形结构时，抛 `IndexError`/`KeyError`/`TypeError`
- engine 的 advisory 分支只捕获 `(ValueError, OSError, RuntimeError)`，上述异常逃逸到 `execute()` 外层 `except Exception`，把本来完成的审查改成 `failed`

**修复**：
- 在模型层把响应解析统一包装，任何 `KeyError`/`IndexError`/`TypeError`/`ValueError` 转为 `ModelUnavailable`（它是 `RuntimeError` 子类，advisory 边界能自然捕获）
- 保留原始异常作为 `cause`，错误信息含异常类型与片段，便于诊断
- 不放宽 engine 的异常捕获面——避免掩盖真实 bug

**测试**：
- `tests/test_model.py`：4 个参数化用例（空 choices / 缺 message / 非 JSON / 错误结构）验证都抛 `ModelUnavailable`
- `tests/test_advisory_failure_boundary.py`：端到端——扫描器不可用产生 coverage warning → 模型翻译抛错 → 审查仍 `completed`、38+ findings 保留、warning 保留

---

### 修复 2：依赖清单不再被自动排除移除

**定位**：`localguard/discovery.py` 的 `NON_SOURCE_NAMES`；`localguard/engine.py` 的 `snapshot()`

**根因**：
- `package-lock.json`、`cargo.lock`、`poetry.lock` 等被 `classify()` 归为 `non-source artifact` 排除
- 但 `scanners.py` 的 `_manifest_lines()` 需要这些文件把 CVE 精确定位到包/版本行
- 定位失败的匹配走 `Omitted unlocated dependency` 分支被丢弃——依赖 CVE 被静默漏掉

**修复**：
- 新增 `DEPENDENCY_MANIFESTS` 常量（`package.json` + 各类 lockfile）
- `snapshot()` 增加 `keep_manifests` 参数；`include_dependencies=True` 时这些文件豁免自动排除
- 验证过 patterns/semgrep 对 lockfile 是零发现，所以代码扫描器看到它们无副作用

**测试**：`tests/test_dependency_snapshot.py` — `keep_manifests=True` 时 lockfile 在快照 hashes 中，`False` 时被排除且在 skipped 列表有记录

**注意**：测试样本不能用 `fixtures/vulnerable.*`（带 `STATIC FIXTURE ONLY` 声明会触发 auto_exclude 整体关闭，掩盖行为）

---

### 修复 3：扫描缓存加入环境指纹与 TTL

**定位**：`localguard/storage.py` 的 `cache_get()`；`localguard/engine.py` 的缓存键构造

**根因**：
- `cache_get()` 只按 key 查，不检查 `created`/TTL；过期条目只有在下次 `cache_put()` 时才被顺带清理
- 缓存键只含扫描器名 + `rules/*.json` 的 mtime + 快照 digest，遗漏：
  - `gitleaks.toml`、`grype.yaml`（非 JSON 配置）
  - 扫描器二进制路径/大小/修改时间（工具升级）
  - Grype 漏洞数据库指纹

**修复**：
- `cache_get(key, ttl=86400)` 读时检查时间，过期视为未命中
- 提取 `scan_cache_key(scanner, hashes, config, rules_dir)` 纯函数，纳入：
  - 全部规则文件（不限 `*.json`）的 name/size/mtime_ns
  - 该扫描器二进制的 size/mtime_ns（或 `no-binary` 标记）
  - Grype DB 指纹（读环境变量 `GRYPE_DB_CACHE_DIR`，与 `scanners.py` 同源）的目录项 name/size/mtime_ns
  - 快照文件 digests
- 仍只缓存 `status == 'completed'` 的结果，不可用/超时/截断不缓存

**测试**：`tests/test_scan_cache.py` 5 项 — 非 JSON 配置变化、二进制版本变化、Grype DB 变化、快照 digest 变化都导致 key 变化；TTL 过期返回 None
**验证**：A/B 审查确认缓存仍正常命中（第二次 `cache_hits=['patterns']`，两次 issues 完全一致），增强指纹没有让缓存失效

---

### 修复 4：日志游标不再饥饿

**定位**：`localguard/storage.py` 的 `recent_logs()`；`localguard/static/app.js` 的 `appendLogs()`

**根因**：
- `recent_logs()` 在 SQL 里先 `LIMIT ?`，再在 Python 里过滤 `tool_evidence` 和 UI 轮询噪声（`get_audit_status` 等）
- 前端按实际返回条目的 `id` 推进 `logSince`
- 若前 100 条全是静默事件 → 返回空列表 → `logSince` 不推进 → 后续真实事件永远到不了

**修复**：
- 把静默事件过滤下沉到 SQL 的 `WHERE`：
  - `event NOT IN (tool_evidence)`
  - `NOT (event='tool_call' AND tool_name IN (静默工具列表))`
- `LIMIT` 只作用于可见事件，游标自然单调推进
- 保留 Python 层过滤作为防御

**测试**：`tests/test_audit_logs.py` 新增用例 — 插入 150 条静默事件 + 1 条真实事件，`recent_logs(limit=10)` 仍能读到真实事件

---

### 修复 5：交付脚本与文档数字对齐

**定位**：`scripts/verify_offline_install.py`；`README.md`

**根因**：
- 离线验证脚本断言 `len(tools) == 8`，而协议已扩展到 11 个工具
- 同一脚本设置 `include_dependencies=False`，却断言结果里有 `dependency_cve` issue——逻辑上不可能成立
- README 的测试数（373）和召回率（62.5%）落后于实际（403 / 87.5%）

**修复**：
- 工具数断言改为"必需工具存在"检查（`audit_repository`、`get_audit_status`、`view_file`、`list_audits`、`cancel_audit`），不再写死数量
- `include_dependencies` 改为 `True`，保持依赖 CVE 断言
- README：测试数 373→403，召回率说明改为"当时 62.5%，现基准 87.5%"（保留历史语境，不篡改当时的叙述）

---

## 三、验证结果

| 项目 | 结果 |
|---|---|
| 全套测试 | **403 passed, 86 subtests, 0 failed**（391 原有 + 12 新增）|
| 召回门禁 | **14/16 = 87.5%**，不退化 |
| 三个扫描器 coverage | 全部 `completed` |
| 缓存有效性 | 第二次审查仍命中缓存，issues 完全一致 |
| GitHub 内容 | 11 个文件逐字节 sha256 核实一致 |

---

## 四、改动文件清单

**源码（5）**
- `localguard/engine.py` — 缓存指纹函数、依赖清单豁免
- `localguard/model.py` — 模型响应异常归一化
- `localguard/storage.py` — 缓存 TTL、日志 SQL 过滤
- `scripts/verify_offline_install.py` — 工具断言、依赖开关
- `README.md` — 数字对齐

**测试（5，其中 3 新增）**
- `tests/test_advisory_failure_boundary.py`（新增）
- `tests/test_dependency_snapshot.py`（新增）
- `tests/test_scan_cache.py`（新增）
- `tests/test_audit_logs.py`（+1 用例）
- `tests/test_model.py`（+5 用例）

**文档（1）**
- `PROJECT_OPTIMIZATION_REPORT.md`（用户提供的输入报告，随提交入库作为记录）

---

## 五、未纳入本次的范围（需单独立项）

报告第 5–9 项是**合理的架构优化建议，但不是已存在的缺陷**。它们改动大、需要真实数据支撑，盲改可能引入退化：

- **基准质量门禁**：正负样本集、多级匹配、scanner coverage 门禁、锁定样本 commit。当前只有 16 个正样本，建立负样本集本身是个数据工程任务
- **大仓库 I/O**：增量快照只物化变更文件、目录枚举移入线程、批量位置校验。需要大仓库实测数据判断收益
- **风险感知截断**：每规则配额、同位置聚类。需对抗顺序测试验证"低优先级规则不挤掉高风险发现"
- **worker/SQLite 规模化**：异常隔离、DB I/O 移入线程、session TTL、前端虚拟列表。需要锁竞争和大报告的实测指标
- **模型评估扩样**：分组 holdout、bootstrap 置信区间。当前 held-out 只有 7 条，扩大样本需要真实标注数据

建议顺序：先建立度量基线（可观测性），再根据数据决定动哪一块，避免"优化"变成无依据的重构。

---

## 六、同步状态

| 仓库 | HEAD |
|---|---|
| 本地 `E:/LocalMD` | `ddc6657` |
| GitCode | `ddc6657` |
| GitHub | API 兜底提交（内容与本地逐字节一致，hash 因兜底不同）|

GitHub 因历史 API 兜底造成的分叉，普通 push 被拒，按工程约定用 contents API 兜底同步了 11 个文件。
