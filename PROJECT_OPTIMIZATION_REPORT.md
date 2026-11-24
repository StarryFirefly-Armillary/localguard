# LocalGuard 项目优化建议报告

- 审查日期：2026-11-24
- 审查对象：`E:\LocalMD`
- 审查方式：只读静态审查，核对源码、测试、CI、基准脚本、交付脚本与项目文档
- 文件改动：仅新增本报告；未修改项目源码、配置或测试
- 验证边界：未启动服务、未运行会写入数据库或缓存的测试，因此不声明当前测试套件或运行时全绿

## 一、结论摘要

LocalGuard 的核心架构已经比较稳定：UI 与 MCP 共用工具链，确定性扫描器负责发现问题，独立校验层负责证据，模型仅承担解释和分诊。项目当前最值得投入的不是继续扩大规则数量或模型权限，而是以下三个方向：

1. **正确性**：避免辅助功能、缓存和自动排除破坏确定性审查结果。
2. **可度量性**：让检出率、误报率、覆盖率和性能数字可以被重复验证。
3. **规模化**：降低大仓库、大报告和高频轮询下的 I/O、数据库与前端压力。

建议先完成第一组正确性修复，再建立质量门禁，最后推进性能和产品化优化。

## 二、现有优势

- UI、CLI、MCP 共享同一 Tool Registry、校验层和报告协议，不存在两套审查逻辑。
- 发现来自确定性工具，模型不能凭空产生可信行号或增删问题。
- 报告落盘前有位置、文件哈希和代码片段校验，核心证据链设计合理。
- 扫描器具备进程清理、输出上限、路径边界和离线约束。
- 已具备人工复核、基线对比、反馈排序、取消任务、离线打包和基准脚本等产品能力。

这些优势应继续保留。后续优化不应削弱“确定性发现优先、模型建议可降级”的纪律。

## 三、第一优先级：正确性修复

### 1. 模型辅助功能仍可能拖垮整次审查

**定位**

- [localguard/model.py:555](file:///E:/LocalMD/localguard/model.py#L555)
- [localguard/engine.py:442](file:///E:/LocalMD/localguard/engine.py#L442)

**证据**

`explain_warnings()` 直接读取 `response['choices'][0]['message']['content']`，没有统一处理 `choices` 缺失、空数组或结构错误。引擎 advisory 分支只捕获 `ValueError`、`OSError`、`RuntimeError`，因此 `KeyError`、`IndexError`、`TypeError` 可能逃逸。

**影响**

模型返回畸形响应时，本来应降级的提示翻译可能让整次审查进入失败状态，违背“模型失败不影响确定性报告”的设计目标。

**建议**

- 在模型层统一规范化响应结构，所有解析失败转换为 `ModelUnavailable`。
- 引擎对 advisory 模型功能使用明确的失败边界，保留原始 warning 和确定性 findings。
- 增加测试：模型返回空 `choices`、错误 JSON、缺字段时，审查仍完成且 findings 不丢失。

**验收标准**

任何模型解析异常都不会把已通过的确定性审查改成失败；报告中出现可解释的降级 warning。

---

### 2. 自动排除与依赖扫描存在冲突

**定位**

- [localguard/discovery.py:77](file:///E:/LocalMD/localguard/discovery.py#L77)
- [localguard/engine.py:263](file:///E:/LocalMD/localguard/engine.py#L263)
- [localguard/engine.py:269](file:///E:/LocalMD/localguard/engine.py#L269)

**证据**

`discovery.classify()` 会把 `package-lock.json`、`yarn.lock`、`Cargo.lock` 等视为非源码产物。引擎却对所有扫描器使用同一份自动排除后的快照；当 `include_dependencies=True` 时，Grype 等依赖扫描器可能无法读取这些关键清单。

**影响**

依赖 CVE 可能被静默漏掉，而报告只显示“自动排除了非源码文件”，用户不一定能意识到这也影响了依赖覆盖。

**建议**

- 将快照拆分为“代码扫描快照”和“依赖扫描快照”。
- 代码扫描继续排除 lockfile、生成目录和压缩产物；依赖扫描保留 manifest/lockfile。
- 对依赖扫描单独记录纳入的清单文件和排除原因。
- 增加端到端测试：项目含 `package-lock.json` 或 `requirements.txt`，启用依赖扫描后能产生预期 CVE。

**验收标准**

自动排除不会移除依赖扫描所需输入；每类扫描器的实际覆盖文件可解释、可核对。

---

### 3. 扫描缓存可能返回过期安全结果

**定位**

- [localguard/engine.py:280](file:///E:/LocalMD/localguard/engine.py#L280)
- [localguard/storage.py:326](file:///E:/LocalMD/localguard/storage.py#L326)

**证据**

当前缓存键包含扫描器名、`rules/*.json` 的 mtime 和快照文件哈希，但遗漏：

- 扫描器二进制路径、版本或内容指纹；
- `gitleaks.toml`、`grype.yaml` 等非 JSON 配置；
- Grype 漏洞数据库版本或指纹；
- 影响扫描行为的配置项。

`cache_get()` 只按 key 查询，不检查 `created` 和 TTL；旧条目只有在 `cache_put()` 时才被清理。

**影响**

工具升级、规则配置修改或漏洞库更新后，旧扫描结果仍可能命中，导致过期 CVE、过期规则行为或错误覆盖状态。

**建议**

- 缓存键加入工具版本/二进制摘要、全部相关配置内容哈希、Grype DB 指纹。
- `cache_get()` 执行 TTL 检查，过期条目直接视为未命中。
- 对不可用、超时、截断或不确定状态默认不缓存，除非有明确的失效策略。
- 增加测试：工具版本、规则配置或 DB 指纹变化后缓存必须失效。

**验收标准**

相同输入且运行环境未变时才允许命中；运行环境变化后必须重新扫描。

---

### 4. 实时日志存在游标饥饿

**定位**

- [localguard/storage.py:114](file:///E:/LocalMD/localguard/storage.py#L114)
- [localguard/static/app.js:481](file:///E:/LocalMD/localguard/static/app.js#L481)

**证据**

`recent_logs()` 先对原始日志执行 `LIMIT`，再在 Python 中过滤 `tool_evidence`、状态轮询等静默事件。前端只根据实际返回条目推进 `logSince`。如果前 100 条都是静默事件，查询会一直返回空列表，后续真实事件永远无法到达。

**影响**

实时日志控制台会在高噪声审查中停止更新，用户误以为后台没有进展。

**建议**

- 在 SQL 中完成可过滤条件的筛选，或者返回独立的 `next_cursor/scanned_to`。
- 前端根据服务端游标推进，而不是根据可见条目数量推进。
- 增加测试：连续插入超过一页的静默事件后再插入真实事件，真实事件仍可读取。

**验收标准**

静默事件不会阻塞后续日志；游标单调推进且重启轮询后不丢事件。

## 四、第二优先级：质量门禁与性能

### 5. 基准需要升级为真正的质量门禁

**定位**

- [scripts/bench_detection.py:42](file:///E:/LocalMD/scripts/bench_detection.py#L42)
- [scripts/bench_detection.py:88](file:///E:/LocalMD/scripts/bench_detection.py#L88)
- [scripts/bench_detection.py:132](file:///E:/LocalMD/scripts/bench_detection.py#L132)
- [.github/workflows/ci.yml:41](file:///E:/LocalMD/.github/workflows/ci.yml#L41)

**证据**

- 默认按文件匹配，同一文件的一条发现可以命中多个 ground truth。
- 只有 16 个正样本，没有负样本集，无法计算 precision 或 FPR。
- 扫描器列表包含 Gitleaks，但没有强制每个所需扫描器都 `completed`。
- CI 基准只在 schedule/manual 运行，样本仓库克隆 HEAD，结果会随上游变化。
- `bench_history.py` 只比较当前工作区最后一次记录，CI 新工作区无法自然形成跨运行趋势。

**建议**

- 建立正负样本基准，分别报告 precision、recall、FPR 和 scanner coverage。
- 使用函数、CWE、行区间等多级匹配，避免“一报多判”。
- 锁定基准样本 commit、规则包版本和扫描器版本。
- PR 运行轻量正样本门禁，定时任务运行完整正负样本评估。
- 将历史趋势保存为持久 artifact 或受控基线文件。

**验收标准**

基准能发现规则遗漏、误报暴涨、扫描器缺失和样本漂移，而不只是统计命中数量。

---

### 6. 优化快照与重复 I/O

**定位**

- [localguard/engine.py:81](file:///E:/LocalMD/localguard/engine.py#L81)
- [localguard/engine.py:253](file:///E:/LocalMD/localguard/engine.py#L253)
- [localguard/engine.py:311](file:///E:/LocalMD/localguard/engine.py#L311)
- [localguard/storage.py:218](file:///E:/LocalMD/localguard/storage.py#L218)

**证据**

- 普通快照会同步枚举和复制文件，大仓库下可能阻塞事件循环。
- 增量模式仍生成完整 revision 快照，最后才按 diff 过滤 findings。
- revision 分支没有复用普通快照的 `exclude_paths/auto_exclude` 策略。
- `Store.get()` 每次都会解析完整报告、统计全部规则反馈并处理全部 issues；分页和导出会反复调用。

**建议**

- 增量模式只物化变更文件，或复用内容哈希缓存跳过未变文件。
- 将快照复制和目录枚举移入线程，同时保留取消和资源上限。
- 按文件批量读取、批量位置校验，减少同一文件多次打开。
- 报告接口拆为摘要和分页明细；避免每页重算全量数据。

**验收标准**

大仓库审查期间 UI 心跳和日志轮询保持响应；增量模式 I/O 与变更规模相关，而不是与全仓库规模相关。

---

### 7. 让发现截断更偏向高风险

**定位**

- [localguard/scanners.py:180](file:///E:/LocalMD/localguard/scanners.py#L180)
- [localguard/scanners.py:63](file:///E:/LocalMD/localguard/scanners.py#L63)
- [localguard/reporting.py:62](file:///E:/LocalMD/localguard/reporting.py#L62)

**证据**

`MAX_FINDINGS=300` 和 200KB 结果上限采用先到先得式裁剪。宽泛规则先产生大量低价值发现时，可能挤掉后续高风险发现。报告层主要按 issue ID 去重，不同规则命中同一位置时仍可能重复占额度。

**影响**

覆盖率和召回率可能因发现顺序而波动；用户看到大量重复或低价值问题，却缺少真正重要的发现。

**建议**

- 引入每规则配额和风险感知保留策略。
- 对同位置、同 CWE、同根因的发现进行聚类，保留多条 evidence。
- 在结果中持续暴露 `dropped_count`、截断阶段和被截断规则分布。
- 用固定随机顺序和对抗顺序测试，确认高风险发现不会因规则顺序被挤掉。

**验收标准**

增加低优先级规则不会系统性降低高风险发现的保留率。

---

### 8. 加强队列、数据库和前端规模化可靠性

**定位**

- [localguard/engine.py:190](file:///E:/LocalMD/localguard/engine.py#L190)
- [localguard/storage.py:50](file:///E:/LocalMD/localguard/storage.py#L50)
- [localguard/storage.py:183](file:///E:/LocalMD/localguard/storage.py#L183)
- [localguard/web.py:42](file:///E:/LocalMD/localguard/web.py#L42)
- [localguard/static/app.js:430](file:///E:/LocalMD/localguard/static/app.js#L430)

**证据**

- worker 主循环没有异常隔离；`claim()` 或 `execute()` 的未预期异常可能终止整个队列。
- SQLite 连接、事务和同步退避 `sleep` 直接在异步路径执行，锁竞争时可能阻塞 API。
- session 仅保存在内存，没有 TTL；服务重启后旧任务仍在数据库，但会话失联。
- 前端终态仍一次拉取并渲染全部 issue，大报告会占用较多内存和主线程时间。

**建议**

- worker 增加监督、异常隔离、退避重试和心跳。
- 数据库 I/O 移入线程或单写者队列；重试应有总期限。
- 增加日志索引、留存策略、WAL checkpoint 和数据库体积指标。
- session 增加 TTL/持久化策略，并清理孤儿上传和过期会话。
- 大报告采用虚拟列表、增量渲染和 URL 深链保存。

**验收标准**

单次数据库抖动不会永久停止队列；大报告下页面仍可滚动、筛选和导出。

## 五、第三优先级：模型、交付与维护

### 9. 模型质量评估需要更大样本和更诚实的覆盖率

**定位**

- [docs/STATUS.md:31](file:///E:/LocalMD/docs/STATUS.md#L31)
- [localguard/engine.py:416](file:///E:/LocalMD/localguard/engine.py#L416)
- [localguard/model.py:247](file:///E:/LocalMD/localguard/model.py#L247)
- [localguard/schemas.py:95](file:///E:/LocalMD/localguard/schemas.py#L95)

**证据**

训练门控只有 7 个样本，单个负例就会明显改变 FPR，容易过拟合。引擎在 `want_triage=True` 时可能直接标记 `model_triage: completed`，即使实际没有拿到 verdict。外部模型列表缓存没有 TTL。`resource_estimate.vram_mb` 仍在 schema 中，但调度逻辑主要使用 `ram_mb`。

**建议**

- 建立分组 holdout、bootstrap 置信区间和跨版本模型回归门禁。
- 分诊结果报告 `triaged_count/total`，并单独统计 likely_true、likely_false、uncertain。
- 模型列表缓存增加 TTL、手动刷新或端点版本失效机制。
- 显存调度要么真实实现，要么从协议中移除，避免虚假承诺。
- 保持模型仅 advisory，不把模型准确率直接等价为工具检出准确率。

**验收标准**

模型升级只有在独立样本上无退化才能发布；报告不会把未执行的分诊标记为完成。

---

### 10. 补齐交付脚本与文档一致性

**定位**

- [scripts/verify_offline_install.py:28](file:///E:/LocalMD/scripts/verify_offline_install.py#L28)
- [scripts/verify_offline_install.py:45](file:///E:/LocalMD/scripts/verify_offline_install.py#L45)
- [scripts/build_offline_bundle.py:37](file:///E:/LocalMD/scripts/build_offline_bundle.py#L37)
- [README.md:132](file:///E:/LocalMD/README.md#L132)
- [docs/STATUS.md:190](file:///E:/LocalMD/docs/STATUS.md#L190)
- [benchmarks/last-run.json:3](file:///E:/LocalMD/benchmarks/last-run.json#L3)

**证据**

离线验证脚本仍断言 8 个工具，但当前协议已扩展；它同时设置 `include_dependencies=False` 却要求依赖 CVE，逻辑不一致。离线打包脚本硬编码 wheel 版本。README/STATUS 中的测试数和召回率已落后于当前代码与本地基准产物。

**建议**

- 工具数量、版本号、测试数和基准指标从单一事实源生成。
- 离线验证脚本按实际协议验证，并保持“禁用依赖扫描”与“要求依赖结果”的契约一致。
- 离线包在干净 Windows 环境中重建，执行真实安装、启动、审查和导出。
- 历史状态文档按日期归档，当前状态单独生成。
- 为规则和二进制建立来源、许可证和哈希清单，而不是只依赖 ID 前缀检查。

**验收标准**

文档数字可追溯到 artifact；离线包可在目标环境从零安装并完成核心审查。

## 六、建议实施路线

### 阶段 A：正确性修复

1. 模型 advisory 异常边界。
2. 代码快照与依赖快照分离。
3. 缓存指纹和 TTL。
4. 日志游标修复。

每项必须带最小回归测试，优先保证“不丢发现、不伪装覆盖、不返回过期结果”。

### 阶段 B：质量门禁

1. 正负样本基准。
2. scanner coverage 门禁。
3. PR 轻量基准。
4. 风险感知截断与聚类。

目标是从“能跑”升级为“结果可比较、退化可发现”。

### 阶段 C：性能与产品化

1. 增量快照与批量 I/O。
2. SQLite/worker 可靠性。
3. 大报告 UI 虚拟化。
4. 可观测性、离线交付和文档单源化。

## 七、建议持续跟踪的指标

- 正样本 recall、负样本 precision/FPR。
- 各扫描器实际 coverage 和 unavailable 原因。
- 发现截断数量、每规则配额占用、重复聚类率。
- 快照耗时、扫描耗时、位置校验耗时、模型解释耗时。
- 缓存命中率和缓存失效率。
- 队列等待时间、取消成功率、worker 异常次数。
- SQLite 锁等待、WAL 大小、日志增长速率。
- 大报告首屏时间、筛选响应时间和导出耗时。
- 模型分诊覆盖率、人工一致率和 uncertain 比例。

## 八、明确不建议的方向

- 不建议用模型直接删除发现或决定严重度。
- 不建议继续无基准地增加宽泛规则。
- 不建议加载被审查仓库自带的规则或配置。
- 不建议为了性能跳过位置和哈希校验。
- 不建议把“测试通过”或“报告生成成功”当成覆盖完整的证明。

## 九、审查说明

本报告基于当前工作区静态阅读得出。由于用户要求不改代码，本次没有运行测试、服务、模型或基准，也没有验证运行时性能。所有结论均给出源码定位；涉及性能和质量的判断需要在后续实施时用 artifact 和真实环境复测。
