# LocalGuard — 本地优先、证据驱动的代码安全审查 Agent

LocalGuard 是一个**完全本地运行**的代码安全审查工具。输入一个本地文件夹或允许的 Git 仓库，输出按风险排序、精确到 `文件:行号`、UI 可点击跳转的安全问题报告；同时把审查能力作为**原生 MCP Server** 暴露，Claude Desktop / Cursor / Claude Code / Windsurf / Cline 等任何 MCP 客户端都可直接调用，无需启动自带 UI。

核心设计纪律：**准确性不交给 LLM**。所有行号都来自 tree-sitter AST 或静态扫描器输出，密钥/CVE/可疑模式由确定性工具判定，LLM 不能凭空产生行号或凭空增删问题。模型有两项明确职责：**解释**每条已验证发现，以及**分诊**（给出 likely_true / likely_false / uncertain 的判断与理由，作为徽章、筛选与人工复核辅助）。分诊是**建议性**的：不删除问题、不改严重度、不宣称可利用性，**不影响默认排序**（默认顺序为严重度→确定性置信度→路径→行号→ID），每条判断写入审计日志，人工复核可推翻且会留痕。审查范围由**智能排除**收敛：跨生态的测试/夹具/生成目录、文件自声明的非执行样本、非源码产物会被自动跳过并给出原因，可一键关闭；对明确指向样本库本身的审查不生效。检出能力由**产品方维护的离线规则包**提供（`security-extended.json`，92 条 MIT 授权的 VulnShop 规则）；**绝不加载被审查仓库自带的规则**——那是供应链攻击面。

## 能力一览

- **五层单向架构**：接入层（自带 UI / MCP stdio）→ Agent 编排层 → 确定性工具层 → 证据聚合与报告层，UI 与 MCP 共享同一套 Tool Registry、校验层和报告协议，不存在两套审查逻辑。
- **多语言**：tree-sitter 统一解析 Python / JavaScript / TypeScript / Java / Go / Rust / C / C++ / PHP / Ruby / Solidity（通过加载 grammar 扩展，不写死专用逻辑）。
- **确定性扫描器**：内置 `patterns` 规则，并适配 semgrep、gitleaks、gosec、cppcheck、pip-audit、grype；扫描器缺失或离线数据不可用时如实报告 `unavailable`，不伪装成"扫描通过"。
- **定位校验层**：报告落盘前逐条校验 `locations`——路径必须来自本次会话已 `view_file` 的文件、行号必须在最近读取范围内、文件 hash 变化标记 `stale`，失败写入日志作为负样本。
- **异步审查 + 资源队列**：`audit_repository` 立即返回 `audit_id`，`get_audit_status` 轮询进度；共享主机上串行调度，避免 4–8GB 设备多任务加载模型导致 OOM。
- **报告协议**：结构化 JSON issue（severity / category / CWE / confidence / locations / evidence / explanation / remediation / needs_human_review），支持 JSON / Markdown / SARIF 导出。
- **自带 UI**：表单 + 对话双模式、文件树与只读预览、`path:line` 深链高亮、人工复核状态、分页与 stale 提示，仅监听 `127.0.0.1`。
- **安全边界**：路径白名单（`realpath` + 目录校验，拒绝 `..` 穿越与符号链接逃逸）、扫描器/规则枚举白名单、输出截断、工具调用审计日志、MCP `isError` 契约（不向 LLM 抛 Python traceback）。

## 目录结构

```
localguard/            核心包
  engine.py           审查流水线、快照、git diff、增量扫描
  registry.py         Tool Registry、调用校验、日志
  schemas.py          MCP 工具定义（inputSchema/outputSchema 唯一来源）
  mcp_server.py       stdio MCP Server
  web.py / static/    Loopback UI（表单/对话/文件浏览/深链）
  git_evidence.py     Git 路径/hunk 解析、按请求 head 校验的快照
  reporting.py        locations 校验、去重、分级、导出
  scanners.py         确定性扫描器适配与内置规则
  model.py            本地模型编排（rules / 4gb / 8gb 档位）
  parser.py / lines.py  tree-sitter 与 LF 一致的行号索引
  training.py         数据校验、QLoRA、配对评估门控
  rules/              内置扫描规则
tests/                 443 项测试（含真实 semgrep 回归、MCP、定位、安全边界）
scripts/               数据整理、训练、离线打包、验证脚本
fixtures/              非执行的静态测试样本（含 11 语言漏洞与干净对照）
```

## 快速开始

要求 Python ≥ 3.11。

```bash
pip install -e .
# 或安装测试依赖
pip install -e '.[test]'
```

配置用一个受信任的本地 JSON 文件（参见 `localguard.example.json`）：

```json
{
  "allowed_roots": ["C:/work/projects"],
  "data_dir": "C:/work/.localguard",
  "offline": true,
  "model_tier": "rules",
  "binaries": {}
}
```

> `allowed_roots` 是唯一可审查目录；`offline: true` 时不访问网络；扫描器二进制通过绝对路径注册，未注册则如实降级为 `unavailable`。

三种入口：

```bash
# 1) 命令行审查（同一套 registry，轮询到完成后打印 JSON）
python -m localguard --config localguard.example.json audit C:/work/projects --depth standard

# 2) 自带 UI（仅 127.0.0.1）
python -m localguard --config localguard.example.json ui --port 8765

# 3) MCP Server（stdio）
python -m localguard --config localguard.example.json mcp
```

环境自检（不修改任何东西）：`python -m localguard --config localguard.example.json doctor`

### 作为 MCP 客户端配置

`mcp-client.example.json` 示例：

```json
{
  "mcpServers": {
    "localguard": {
      "command": "python",
      "args": ["-m", "localguard", "--config", "/abs/path/localguard.json", "mcp"]
    }
  }
}
```

`tools/list` 暴露 11 个工具：`view_file`、`list_tree`、`get_ast`、`run_scanner`、`git_diff`、`audit_repository`、`get_audit_status`、`cancel_audit`、`list_audits`、`analyze_image`、`clone_repository`（内部 `rank_and_report` 不暴露）。`cancel_audit` 停止正在运行/排队的任务（会终止扫描子进程），`list_audits` 列出本会话最近任务供页面刷新后恢复。`clone_repository` 是唯一联网工具，仅拉取白名单 HTTPS 仓库到本地；审查本身始终离线。自带 UI 调用时需在弹窗中显式确认；MCP 客户端调用不做交互确认，而是受 host 白名单、禁凭据/端口、禁 submodule/hook、`--depth 2` 与目标目录隔离约束——自动化编排依赖这一非交互行为。描述中包含功能边界、参数示例、返回结构与限制，输入在 schema 层用 enum / pattern 约束，输出遵循严格 schema。

典型调用流程：

```
audit_repository(target=<allowed absolute path>, depth=standard)
  -> { audit_id, status: "queued" }
get_audit_status(audit_id=..., wait_seconds=2)
  -> { status, progress, issues:[{locations:[{path,line}], ...}], coverage, warnings }
view_file(path=<abs>, start_line, end_line)   # 深链/证据核对
```

## 模型档位

- `rules`（默认）：纯确定性规则编排，**完全不需要任何模型文件**，适合 4GB 以下设备与离线环境。
- `4gb`：tool-call 路由 + 轻量解释；配置 `model_4gb_path` 指向本地小模型。
- `8gb`：Qwen3.5-4B Q4 GGUF 用于工具调用与解释；配置 `model_binary` / `model_path` / `mmproj_path`。

模型只生成解释与编排，不产生被信任的行号；解释失败时保留确定性发现并给出警告。

**AI 解释条数上限**（`max_model_explanations`，默认 16；UI 高级设置或 `audit_repository` 的 `max_explanations` 可覆盖，0 = 全部）：按风险高低只为前 N 条发现生成 AI 文字解释，其余发现**完整保留** severity、locations、evidence 与人工复核入口，仅标记 `ai_explanation: skipped_budget`、UI 显示「未做 AI 解释」徽章。实测同一审查（133 条发现）：全量解释约 256 秒，上限 16 条约 60 秒，提速约 75%——这是在不删任何发现、不改召回（当时 62.5%，现基准 87.5%）前提下的主要提速手段。

### 没有模型文件怎么办？

**什么都不用做，核心功能完整可用。** 本仓库不包含也不要求任何模型文件。请直接使用默认的 `model_tier: "rules"`：

- `audit` / UI / MCP 三种入口都能跑完整审查：确定性扫描 → locations 校验 → 结构化报告 → 深链跳转，行号来自 tree-sitter / 扫描器，与模型无关。
- 实测：无任何模型文件时对内置 fixtures 执行 `rules` 审查，得到 38 条 issue，`vulnerable.c:4` 等定位准确，`status: completed`。
- 唯一差别：报告的「自然语言解释/修复建议」是规则生成的确定性文本，而不是 LLM 润色版本；`coverage.model_explanation` 不会出现，属于预期行为，不是错误。
- 表单模式、MCP `audit_repository` 本来就不经过 LLM 选工具；只有**对话模式**和**模型解释**才需要模型。选 `rules` 时对话模式退化为确定性路由（见 `model.py` 的 rules 分支）。

想启用模型时，按 `docs/TRAINING.md` 的步骤 A 自行下载一个 GGUF 并填入配置即可；这不是使用本工具的前提。

## 渐进式训练指南

如果你想从"纯 rules"逐步升级到"带本地模型解释"、再到"自己的 QLoRA adapter"，见 **[docs/TRAINING.md](docs/TRAINING.md)**：分阶段给出无需训练 → 现成 GGUF → 数据回流 → QLoRA 门控的完整路径。当前已有一个正负平衡、通过门控并合并的 adapter（FP16 产物，尚未量化为运行时 GGUF），详情见 `docs/STATUS.md`。

## 验证状态

- 测试：`443 passed, 86 subtests`（`pytest -q`）。
- 真实 MCP 客户端联调：Qoder Desktop 与另一 MCP 客户端均完成 `tools/list` 发现、`audit_repository` → `get_audit_status` 轮询、拿到与 UI 一致的结构化 issue（见发布包内的验证记录）。
- 离线安装与审查：在离线环境用打包 wheel + 本地 wheels 安装后完成审查（见 `dist/offline/`）。
- 阶段 5 进展：一个正负平衡的 QLoRA adapter 已训练并通过配对评估门控（FPR 0.4→0.2、AUC 0.7→0.85，各项无退化），已合并并量化为运行时 Q4_K_M GGUF，产品配置已指向该微调模型。确定性扫描器 + 校验层仍是可信来源，模型解释是可选增强。详见 `docs/STATUS.md`。

## 开发与打包

```bash
pytest -q                                   # 全套测试
python scripts/check_licenses.py            # 规则包许可检查
python scripts/bench_detection.py --config localguard.local.json --json benchmarks/last-run.json  # 检出率基准
python scripts/build_offline_bundle.py --no-download   # 生成离线 bundle
```

检出率基准对照 VulnShop 的 16 个已知漏洞（详见 [benchmarks/README.md](benchmarks/README.md)），改动规则或审查流程后可以跑它确认没有退化。CI 在 push/PR 时跑测试与许可检查；完整基准每周一 03:00 UTC 定时触发，也可在 Actions 里手动触发（需扫描器二进制；召回低于 40% 会 fail）。

离线 bundle 包含应用 wheel、应用/扫描器 wheels、扫描器二进制与 Grype DB，供无网络设备安装。仓库不提交虚拟环境、扫描器二进制、模型/数据库等大文件（见 `.gitignore`）。

## 说明

本仓库仅包含源码、测试、脚本与静态测试样本；虚拟环境、扫描器二进制、模型文件、扫描数据库等运行产物未纳入版本控制，需按上述步骤在本地准备。

## 许可

本项目采用 [MIT License](LICENSE)。随项目分发的第三方组件来源与许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 扩展规则包

Semgrep 扫描器每次运行会加载 `localguard/rules/` 下的 `security.json`、`backdoor.json` 和 `security-extended.json`。三者都是**标准 Semgrep 规则格式**（JSON，结构为 `{"rules": [...]}`），你可以在本地编辑它们来增减规则——例如把 `security-extended.json` 替换为你自己整理或已获授权的规则集。改动是本地行为，不需要改代码；重启 UI 服务即可生效。

添加规则前请注意：

- 添加规则前确认你对规则来源拥有相应使用权；第三方规则的许可信息见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
- **规则 id 建议加自己的前缀**，避免与内置规则冲突。
- **规则包不是越多越好**：过多的宽泛规则会放大噪声并被后续的数量/体积上限截断。改完建议用你熟悉的仓库跑一次，确认检出与误报都可接受。
