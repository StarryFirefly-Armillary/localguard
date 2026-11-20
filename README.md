# LocalGuard — 本地优先、证据驱动的代码安全审查 Agent

LocalGuard 是一个**完全本地运行**的代码安全审查工具。输入一个本地文件夹或允许的 Git 仓库，输出按风险排序、精确到 `文件:行号`、UI 可点击跳转的安全问题报告；同时把审查能力作为**原生 MCP Server** 暴露，Claude Desktop / Cursor / Claude Code / Windsurf / Cline 等任何 MCP 客户端都可直接调用，无需启动自带 UI。

核心设计纪律：**准确性不交给 LLM**。所有行号都来自 tree-sitter AST 或静态扫描器输出，密钥/CVE/可疑模式由确定性工具判定；LLM 只负责选工具、串联调用、解释结果与生成分级报告，且不能凭空产生行号。

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
tests/                 345 项测试（含真实 semgrep 回归、MCP、定位、安全边界）
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

`tools/list` 暴露 8 个工具：`view_file`、`list_tree`、`get_ast`、`run_scanner`、`git_diff`、`audit_repository`、`get_audit_status`、`analyze_image`（内部 `rank_and_report` 不暴露）。描述中包含功能边界、参数示例、返回结构与限制，输入在 schema 层用 enum / pattern 约束，输出遵循严格 schema。

典型调用流程：

```
audit_repository(target=<allowed absolute path>, depth=standard)
  -> { audit_id, status: "queued" }
get_audit_status(audit_id=..., wait_seconds=2)
  -> { status, progress, issues:[{locations:[{path,line}], ...}], coverage, warnings }
view_file(path=<abs>, start_line, end_line)   # 深链/证据核对
```

## 模型档位

- `rules`（默认）：纯确定性规则编排，无需模型，适合 4GB 以下设备与离线环境。
- `4gb`：tool-call 路由 + 轻量解释；配置 `model_4gb_path` 指向本地小模型。
- `8gb`：默认 Qwen3.5-4B Q4 GGUF 用于工具调用与解释；配置 `model_binary` / `model_path` / `mmproj_path`。

模型只生成解释与编排，不产生被信任的行号；解释失败时保留确定性发现并给出警告。

## 验证状态

- 测试：`345 passed, 86 subtests`（`pytest -q`）。
- 真实 MCP 客户端联调：Qoder Desktop 与另一 MCP 客户端均完成 `tools/list` 发现、`audit_repository` → `get_audit_status` 轮询、拿到与 UI 一致的结构化 issue（见发布包内的验证记录）。
- 离线安装与审查：在离线环境用打包 wheel + 本地 wheels 安装后完成审查（见 `dist/offline/`）。
- 已知边界：阶段 5 的 QLoRA adapter 仅完成数据/门控/评估脚手架，**配对评估门控未通过，adapter 未合并、未部署**；生产报告由确定性扫描器 + 校验层产出，模型解释始终是可选增强。详见仓库内 `docs/STATUS.md` 与 `docs/evidence/`。

## 开发与打包

```bash
pytest -q                                   # 全套测试
python scripts/build_offline_bundle.py --no-download   # 生成离线 bundle
```

离线 bundle 包含应用 wheel、应用/扫描器 wheels、扫描器二进制与 Grype DB，供无网络设备安装。仓库不提交虚拟环境、扫描器二进制、模型/数据库等大文件（见 `.gitignore`）。

## 说明

本仓库仅包含源码、测试、脚本与静态测试样本；虚拟环境、扫描器二进制、模型文件、扫描数据库等运行产物未纳入版本控制，需按上述步骤在本地准备。
