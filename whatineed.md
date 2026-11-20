# 本地代码安全审查 Agent — 产品开发任务书

你是一名全栈 + AI 工程 agent，负责从零实现一个**本地部署、低显存（4–8GB）、多语言、行号精确可点击，并可打包为 MCP Server 供外部客户端直接调用**的代码安全审查 Agent。以下内容为完整需求与实现约束，请严格按此执行；遇到未明确的细节时，优先选择“确定性优先、LLM 只做编排与解释”的方案。

---

## 一、产品定位（不可偏离的边界）

构建一个本地运行的审查 agent，输入一个项目文件夹或 GitHub 仓库，输出**按风险等级排序、定位到文件:行号、UI 可点击跳转**的安全问题报告，覆盖后门与通用安全漏洞。同时，该 Agent 的**原生审查能力必须通过 MCP（Model Context Protocol）对外暴露**，使 Claude Desktop、Cursor、Claude Code、Windsurf、Cline 等任何 MCP 兼容客户端可以直接调用审查工具，无需启动本产品自带 UI。

**四条硬约束：**

1. **显存 4–8GB**。默认 agent 大脑为 Qwen3.5-4B（Q4 量化，8GB 档）；4GB 档降级为纯 tool-call 路由 + 轻量解释模式（0.8B 级模型或仅规则编排）。
2. **准确性责任不交给 LLM**。LLM 不“裸读代码找后门”。所有行号必须来自 tree-sitter AST 或静态工具输出；所有确定性判断（密钥、依赖 CVE、可疑模式）由外部扫描器完成。LLM 的职责是：选择工具、串联调用、解释工具结果、生成分级报告。
3. **多语言兼容**。以 tree-sitter 统一解析，至少覆盖 Python / JavaScript / TypeScript / Java / Go / Rust / C / C++ / PHP / Ruby / Solidity。语言扩展通过加载 tree-sitter grammar 实现，不允许为每种语言写死专用逻辑。
4. **MCP 是原生接口，不是事后附加**。审查引擎从设计之初就以“可被外部 MCP 客户端调用”为第一等需求；UI 和 MCP Server 共享同一套 Tool Registry、同一套校验层、同一套报告协议，不允许出现两套审查逻辑。

---

## 二、核心架构（五层，单向依赖）

```
┌──────────────────────────────────────────────────────────┐
│  接入层                                                    │
│  自带 UI（表单 / 对话 / 文件浏览器）  │  MCP Server（stdio）  │
└──────────────────────┬───────────────────────────────────┘
                       │  共享 Tool Registry + 统一校验层
┌──────────────────────▼───────────────────────────────────┐
│  Agent 编排层（Qwen3.5-4B，tool call loop）               │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│  确定性工具层（tree-sitter / semgrep / gitleaks / gosec   │
│  / cppcheck / pip-audit / grype / git_diff）              │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│  证据聚合与报告层（去重、误报过滤、风险分级、locations 协议）│
└──────────────────────────────────────────────────────────┘
```

**设计纪律：**

- LLM 只能接触“工具返回的结构化片段”和“已被规则缩小的文件子集”，**禁止把整个仓库或大文件直接灌入 prompt**。仓库级扫描先由启发式 + 规则筛出安全相关文件（默认每轮最多 60 个），再交 LLM 处理。
- 表单模式**不经过 LLM 选工具**，直接把表单字段映射为固定工具序列；对话模式和 MCP 调用才由 LLM 自主编排。
- 扫描工具以队列串行或小并发执行，LLM 调用与工具执行在时间上错开，避免 4–8GB 环境下资源争抢。本地共享主机上的资源调度可参考 ToolSched 的思路：在 MCP 接口中嵌入资源模型，让调用方在请求时附带资源需求估计，服务端结合实时主机状态决定实际执行时机。

---

## 三、工具层定义（共享 Tool Registry）

所有工具必须提供 JSON Schema 描述，并同时被表单 pipeline、对话 agent 和 MCP Server 复用。**工具定义本身就是 MCP 工具的 `inputSchema` / `outputSchema`，不允许为 MCP 另写一套 schema。**[reference:1]

### 必备工具

| 工具名 | 功能 | 关键参数 | MCP 暴露 |
|---|---|---|---|
| `view_file` | 返回带 **1-indexed 行号**的代码切片，行号来自文件真实索引或 AST 节点 | `path`, `start_line`, `end_line` | 是 |
| `list_tree` | 返回目录树，支持忽略规则 | `path`, `max_depth` | 是 |
| `run_scanner` | 调用一个静态扫描器，返回原始 JSON 结果 | `scanner`, `target`, `ruleset` | 是 |
| `get_ast` | 返回指定文件/函数的 AST 结构摘要（含节点行号范围） | `path`, `node_type` | 是 |
| `git_diff` | 提取增量 diff | `repo`, `base`, `head` | 是 |
| `analyze_image` | 多模态辅助：解析架构图/终端截图 | `image_path`, `question` | 是（可选） |
| `audit_repository` | **MCP 核心审查入口**：对目标仓库执行完整审查 pipeline，返回结构化 issue 列表 | `target`, `depth`, `scanners`, `include_dependencies` | 是 |
| `get_audit_status` | **异步查询**：根据 `audit_id` 返回进度、已完成模块、初步发现 | `audit_id` | 是 |
| `rank_and_report` | 汇总证据，输出符合 locations 协议的报告 | 内部调用 | 否（内部） |

### 定位校验层（必须实现，不可省略）

在 `rank_and_report` 落盘前，对每一条 issue 的 `locations` 做硬校验：

1. `path` 必须出现在本次会话已读取文件集合中，否则拒绝并要求先 `view_file`；
2. `line` 必须落在该文件最近一次 `view_file` 返回的 `[start_line, end_line]` 范围内，否则拒绝并返回错误让模型重读；
3. 文件读取后 hash 变化 → 标记该 location 为 `stale`，要求重新读取；
4. 校验失败时记录到会话日志，作为后续微调数据的负样本。

---

## 四、MCP Server 专项需求（本次新增，优先级等同核心功能）

### 4.1 传输与兼容

- **传输方式**：以 **stdio** 为首要传输，兼容 Claude Desktop、Cursor、Claude Code、Windsurf、Cline 等客户端的本地 MCP 配置模式[reference:2][reference:3]。HTTP/SSE 作为可选扩展，不阻塞首版交付。
- **启动命令**：提供可执行入口，使客户端能以 `command` + `args` 方式配置，例如 `uvx <package> mcp` 或 `python -m <module> mcp`，参考 Semgrep MCP 和 GRIM 的发布方式[reference:4][reference:5]。
- **工具发现**：MCP Server 启动后必须通过 `tools/list` 暴露审查相关工具及其完整 schema，任何兼容客户端应能“开箱即用”地发现 `audit_repository`、`view_file`、`run_scanner` 等能力[reference:6]。

### 4.2 MCP 工具设计约束

- **单一职责**：MCP Server 只暴露“审查执行”和“证据查询”类工具，不暴露配置管理、模型切换、用户偏好设置等治理型操作。治理能力（API key、扫描器白名单、并发上限）通过配置文件或环境变量管理，不走 tool call[reference:7]。
- **描述极度清晰**：每个 MCP 工具的 `description` 必须包含：功能边界、参数格式（含示例）、返回结构摘要、已知限制。LLM 完全依赖 `description` 和 `inputSchema` 决定是否调用，描述不清晰是误调用的首要根源[reference:8]。
- **输入校验在 schema 层完成**：`target` 必须是本地绝对路径或合法 Git URL；`depth` 用 enum 约束（`quick`/`standard`/`deep`）；`scanners` 用 enum 数组约束；禁止自由文本透传为扫描器参数[reference:9]。
- **输出 schema 严格化**：`audit_repository` 返回的 `outputSchema` 必须包含 issue 数组，每个 issue 必须有 `locations` 字段（`path` + `line`），且行号已经过第三节校验层。客户端可据此做结构化消费或 UI 渲染[reference:10]。
- **错误即内容**：工具执行失败（目标路径不存在、扫描器超时、模型 OOM）以 `isError: true` 的 tool result 返回可读错误信息，不抛出异常栈。LLM 可以从“无法访问目标路径”中恢复，无法从 Python traceback 中恢复[reference:11][reference:12]。

### 4.3 审查任务的长时运行与超时策略

完整仓库审查是长任务，可能在数分钟到数十分钟不等，**不能阻塞 MCP 客户端的主对话循环**。必须采用**异步 + 轮询**模式：

1. `audit_repository` 接受请求后立即返回 `{ "audit_id": "...", "status": "queued" }`，审查在后台执行；
2. 客户端通过 `get_audit_status(audit_id)` 轮询进度，参数可包含 `wait_seconds`（短轮询，建议 ≤ 30s）以避免客户端侧 tool timeout；
3. 审查完成后，`get_audit_status` 返回完整 issue 列表，结构与 UI 侧报告协议完全一致；
4. 提供可选的 `notification` 机制（如果目标客户端支持 MCP notifications），但不作为唯一完成通知路径。

参考 Semgrep Guardian 的“hook / MCP tool call 触发扫描、结果回传 agent 决策”模式，以及 GRIM 将 Python 引擎作为 stdio MCP Server 运行的发布形态[reference:13][reference:14]。

### 4.4 并发与资源隔离

- MCP Server 可能同时服务于多个外部客户端和自带 UI，**共享同一台 4–8GB 主机**。必须内置一个**审查任务队列**，对 `audit_repository` 做串行或低并发调度，避免多个审查任务同时加载 4B 模型导致 OOM。
- 队列状态通过 `get_audit_status` 的 `queue_position` 字段暴露给客户端，让调用方知道“为什么还没开始”。
- 单次审查结束后释放模型显存或保持最小驻留，由配置项 `keep_model_resident` 控制（默认 `false`，即审查完成后卸载模型，下次调用重新加载）。

### 4.5 MCP 侧安全边界（不可省略）

- **不信任调用方**：MCP Server 收到的 `target` 不能直接拼接进 shell 命令。所有路径经 `realpath` 规范化和白名单目录校验，禁止 `..` 穿越和符号链接逃逸。
- **扫描器参数白名单**：`run_scanner` 的 `scanner` 和 `ruleset` 参数经 enum 校验，禁止 MCP 客户端传入任意 `--config` 路径（防规则注入/供应链攻击）。
- **工具输出截断**：MCP tool result 的内容长度上限固定（例如 200KB 或 50k token），超出部分截断并标记 `truncated: true`，防止恶意仓库撑爆客户端上下文。
- **调用审计日志**：每次 MCP tool call 记录 `client_name`、`tool_name`、`target`、`audit_id`、耗时、校验结果，写入本地日志文件，供事后审计和微调数据回流使用。

---

## 五、报告数据协议（UI、MCP、微调数据三者共用）

每条 issue 必须输出结构化 JSON，**不允许用自然语言“第 X 行”代替结构化字段**：

```json
{
  "id": "ISSUE-001",
  "title": "硬编码 AWS 密钥",
  "severity": "high",
  "category": "credential_leak | injection | backdoor | dependency_cve | misconfig | other",
  "cwe": "CWE-798",
  "confidence": 0.87,
  "locations": [
    {"path": "src/config/settings.py", "line": 47, "snippet_hash": "..."}
  ],
  "evidence": [
    {"tool": "gitleaks", "raw_ref": "..."},
    {"tool": "view_file", "range": [40, 55]}
  ],
  "explanation": "……（LLM 生成的上下文解释，不得包含未经工具验证的行号）",
  "remediation": "……",
  "needs_human_review": true
}
```

**排序规则**：severity 降序 → confidence 降序 → 同文件聚合。高风险项默认 `needs_human_review: true`，UI 必须显示人工确认入口，MCP 输出必须保留该字段。

---

## 六、模型方案

### 基座
Qwen3.5-4B，Q4 量化，8GB 档 100% GPU 卸载；4GB 档使用 0.8B 级模型做路由 + 规则编排。

### 微调方法
**QLoRA**（4-bit 基座 + LoRA rank 16–32，序列长度 4096，梯度累积小批量）。产出 adapter 几十至几百 MB，推理时合并，显存不增加。

### 训练数据三层组合（缺一不可）

1. **CVE 补丁对比数据**：从 fix commit 构造“漏洞版本 / 修复版本 / 同文件未变函数”三元组，教模型学习“什么变化消除了缺陷”，而非死记模式。
2. **多轮安全审查对话数据**：覆盖 OWASP Top 10、多语言，每条样本锚定真实 CVE/安全事件，包含“漏洞实现 vs 安全实现 + 攻击演示 + 修复建议”结构，对齐本产品的报告格式。
3. **工具调用格式数据（最关键）** ：每条报告样本必须附带真实的 `view_file` 调用和结构化 `locations`，训练模型“先读、再引用”的工作流。**格式一致性优先于数据量**——样本中禁止出现纯文本“第 47 行”式的位置描述。

### 后门检测的训练策略
公开后门样本稀少，**不训练“从干净代码直接识别后门”**。训练模型做两件事：（a）对静态工具标记的可疑片段做上下文关联与解释；（b）对 `git_diff` 生成的修复前后对比做判断（后门移除通常伴随特定分支或外部地址消失）。

### 评估指标
漏洞检测准确率、**误报率**、CWE 分类准确率、**行号引用准确率**、**tool call 格式成功率**。参考线：漏洞排序 AUC 约 0.8 为“良好”，不要期望误报接近零。

---

## 七、UI 需求

### 双模式入口

**表单模式**：字段包括目标仓库/文件夹路径、扫描器集合勾选、审查深度、是否含依赖审计、是否增量、模型档位。提交后直接执行固定 pipeline，输出结构化报告。

**对话模式**：用户自然语言描述审查意图，agent 自主编排工具。支持拖入图片（架构图/终端截图），调用 `analyze_image` 作为辅助输入，**多模态是辅助通道，不是核心审查路径**。

### 文件浏览器与深链

- 左侧文件树 + 右侧只读预览面板；tree-sitter 做语法高亮与行号索引，**与 agent 侧 `view_file` 共享同一套解析结果**。
- 报告中每个 `locations` 渲染为可点击的 `path:line` 链接；点击后打开文件、滚动到目标行并高亮。
- 支持 `stale` 状态提示。
- 每条 issue 卡片展示 severity、category、evidence 来源、人工复核按钮。

---

## 八、安全与沙箱

1. **命令白名单**：`run_scanner` 只允许调用预注册的扫描器二进制，参数经 schema 校验，禁止透传目标仓库中的配置。
2. **输出大小限制**：工具返回截断到固定上限。
3. **审查目标隔离**：扫描进程在受限目录内运行，不执行目标仓库中的构建脚本。
4. **工具调用日志**：完整记录入参、返回摘要、校验结果，用于审计与微调数据回流。
5. **MCP 侧额外约束**：见第四节 4.5。

---

## 九、建议的落地顺序

**阶段 1 — 定位闭环（不依赖微调）**
实现 `view_file` + tree-sitter 行号索引 + locations 校验层 + UI 深链跳转。用未微调的 Qwen3.5-4B 跑通全链路。验收：行号精确高亮，校验层拒绝率可观测。

**阶段 2 — 确定性扫描接入**
接入 semgrep（含自定义后门规则包）、gitleaks、依赖审计工具，表单模式 pipeline 跑通。验收：干净仓库误报可控，已知漏洞定位到正确行。

**阶段 3 — 对话模式与 tool call 稳定性**
接入对话 agent loop，验证 4B 模型 tool call 格式成功率。验收：格式退化率低于可接受阈值，失败可自动重试。

**阶段 4 — MCP Server 封装（与阶段 1–3 并行可，但必须在阶段 5 之前完成）**
将 Tool Registry 中的审查工具以 stdio MCP Server 形式暴露，实现 `audit_repository` 异步模式 + `get_audit_status` 轮询，完成与至少两个主流客户端（如 Claude Desktop 和 Cursor）的联调。验收：外部客户端能发现工具、发起审查、轮询并拿到与 UI 完全一致的结构化 issue 列表。

**阶段 5 — 微调与数据回流**
用阶段 1–4 产生的真实交互日志（含 MCP 调用日志和校验失败负样本）构造三层训练数据，完成 QLoRA 微调。验收：行号引用准确率与 tool call 成功率不下降，误报率有可量化改善。

**阶段 6 — 多模态辅助与报告打磨**
接入 `analyze_image`，完善风险分级、evidence 展示、导出格式（JSON/Markdown/SARIF）。

---

## 十、最终验收标准

- 4GB 与 8GB 档位均可在消费级设备本地启动，无网络依赖。
- 对一个含已知漏洞与后门样本的多语言仓库，报告能定位到**正确的文件与行号**，UI 点击可精确高亮。
- 干净仓库上的误报数量在可接受范围，高风险项均带人工复核入口与 evidence 链。
- 表单模式结果稳定可复现；对话模式 tool call 格式成功率达标。
- **MCP Server 可被 Claude Desktop / Cursor 等客户端直接配置使用**：`tools/list` 能发现审查工具，`audit_repository` 返回 `audit_id`，`get_audit_status` 能轮询到与 UI 结构一致的 issue 列表。
- **不存在两套审查逻辑**：MCP 调用和 UI 调用走同一套 Tool Registry、同一套 locations 校验层、同一套报告协议。
- 所有 LLM 声称的位置都经过校验层，**不存在未经工具验证的行号进入最终报告**。
- 工具调用在沙箱与白名单约束下执行，日志完整可审计。

---

**执行时请优先保证“确定性定位闭环”和“MCP 原生接口”先于“模型能力提升”**：先让系统在未微调模型上输出可验证、可点击、可被外部 MCP 客户端调用的报告，再用真实交互数据驱动微调。任何为了让模型“看起来更聪明”而绕过 locations 校验层、直接让 LLM 生成行号，或为 MCP 另写一套独立审查逻辑的做法，都视为偏离本任务书。