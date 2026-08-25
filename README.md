# AWDP Scanner

面向 CTF AWD/AWDP 防守场景的离线优先源码审计与补丁验证工具。它用于赛前加固、开局审计和人工修复决策，不提供攻击自动化、flag 获取、持久化或破坏能力。

核心原则是：静态分析提供事实路径，LLM 处理难以建模的语义，RAG 只约束修复策略，补丁必须在隔离副本中验证，任何失败都不能被包装成“安全”。

## 当前能力

- Python 项目级 AST、调用图、跨文件参数传播和 source→sink 程序切片。
- PHP、JavaScript/Node、Java/JSP、Go 的保守规则候选与未知来源高危 sink 提醒。
- Ollama JSON Schema 检测/修复输出；格式错误自动转人工复核。
- 默认仅允许回环 Ollama，禁用环境代理和重定向；远端模型必须显式授权。
- Chroma 本地 RAG，支持 family/语言/角色元数据、混合重排、来源多样性和版本哈希。
- Markdown、JSON、SARIF、run manifest、内容寻址增量缓存。
- 在临时项目副本中应用候选补丁，执行语法检查和显式配置的回归命令，原源码不被修改。
- 确定性回归基准、pytest、Ruff、CodeQL、依赖审计、SBOM 与发布构建工作流。

## 结论语义

| 状态 | 含义 | 操作 |
|---|---|---|
| `VULN` | 达到明确疑似阈值 | 优先人工确认并修复 |
| `WARN` | 证据存在但需人工复核，或模型/验证失败安全降级 | 检查 source→sink 路径和上下文 |
| `SAFE` | 已完成相应分析并得到安全结论 | 仍不代表整个项目无漏洞 |
| `NO-CANDIDATE` | 预筛未命中，未执行深度模型分析 | 不是安全证明 |
| `NOT-ANALYZED` | 文件读取、分析器或执行流程失败 | 必须补扫 |

特别注意：`NO-CANDIDATE` 与 `SAFE` 被严格分离；解析失败、模型失败、Schema 失败和工具失败均不会返回安全。

## 安装

Python 3.10 或更新版本：

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e .
```

启用本地向量知识库：

```bash
python -m pip install -e ".[rag]"
```

开发环境：

```bash
python -m pip install -e ".[dev]"
```

## 离线准备

1. 在可信联网环境中安装依赖、Ollama 模型和 embedding 模型。
2. 把 embedding 模型完整放入 `models/<模型名>/`，不要依赖运行时下载。
3. 保持 `OLLAMA_BASE_URL=http://localhost:11434`。
4. 构建知识库：

```bash
python build_vector_db.py
```

知识库先写入临时目录，生成标签、chunk、语料和 embedding SHA-256 元数据，再事务式切换；失败时旧库保持不变。

## 扫描

```bash
awdp-scanner --target /path/to/target
```

常用选项：

```bash
awdp-scanner \
  --target /path/to/target \
  --output-dir ./awdp_runs/opening-scan \
  --no-rag \
  --no-cache \
  --verify-patches
```

需要测量模型本身的条件能力时，可用 `--deep-all` 跳过候选门控；只做检测、不消耗第二次模型调用生成修复时，可加 `--no-generate-repairs`。这两个选项适合评测和人工控制的深审，不应被理解为所有文件都能得到可靠结论。

只有在操作者明确授权执行目标项目测试时，才传入回归命令：

```bash
awdp-scanner --target ./target_code \
  --patch-test-command "python -m pytest -q" \
  --patch-test-timeout 60
```

目标仓库测试属于不可信代码。这个选项不提供 OS 级沙箱；正式比赛环境应在无网络、无凭据、低权限的容器或虚拟机中运行整个扫描器。

每次运行默认写入唯一的 `awdp_runs/<run-id>/`：

```text
report.md          人工阅读报告
findings.json      结构化完整结果
results.sarif      GitHub/IDE/安全平台交换格式
manifest.json      配置、版本、哈希、摘要、缓存和补丁验证记录
patches/*.diff     隔离验证过或验证失败的候选差异
```

## 严格离线边界

- 默认只接受 `localhost`、`127.0.0.0/8` 和 `::1` 模型端点。
- HTTP 会话 `trust_env=False`，不继承代理或隐式认证，并拒绝重定向。
- embedding 加载必须支持 `local_files_only=True`；不兼容时失败关闭。
- `--allow-remote-model` 是显式数据外传授权，使用前应确认比赛规则和源码保密要求。

## 架构

```text
安全发现 → 语言规则/AST → 项目调用图与污点传播 → 程序切片
        → LLM Schema 判定 → RAG 修复约束 → 候选补丁
        → 临时副本验证 → Markdown/JSON/SARIF/manifest
```

实现已拆分为 `awdp_scanner.analysis`、`models`、`reporters`、`cache`、`patching`、`rag` 和 `benchmark`。详细信任边界见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) 与 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)。

## 基准与质量门槛

```bash
ruff check .
python -m pytest -q
awdp-benchmark --corpus benchmarks/corpus.json --output benchmark-result.json
python -m build
```

仓库内置基准是小型确定性回归集，用于防止已知能力倒退，不能外推为真实世界准确率。严肃评测应采用去重、按时间切分的 vulnerable/fixed 对、跨文件变形测试和固定人工复核预算。研究依据见 [`docs/RESEARCH_FOUNDATIONS.md`](docs/RESEARCH_FOUNDATIONS.md)。

真实 Ollama/硬件基准使用固定提交、逐文件 SHA-256 校验的 Probely CTF 子集。首次显式下载语料：

```bash
awdp-model-benchmark --prepare \
  --model qwen2.5-coder:14b \
  --output-dir benchmarks/.results/qwen14b
```

后续运行去掉 `--prepare` 即保持离线；可用多个 `--model` 比较模型，或用多个 `--case <id>` 做定向实验。该工具只读取题目源码，不启动题目、不执行 PoC 或目标测试。当前实机结果、Intel Arc Vulkan 配置和指标解释见 [`docs/REAL_MODEL_BENCHMARK_2026-08-25.md`](docs/REAL_MODEL_BENCHMARK_2026-08-25.md)。

## 已知边界

- “完美扫描器”不存在；未命中不等于无漏洞。
- 当前一等语义前端是 Python；其他语言仍以保守规则和人工复核为主。
- Python 分析目前是上下文不敏感、有限控制流合并，不处理反射、运行时 monkey patch、C 扩展和所有框架隐式数据流。
- 模型 `confidence` 不是校准后的真实概率。
- 语法通过不代表补丁功能正确；只有显式功能/安全回归也通过时，补丁证据才更强。
- 本项目不是恶意代码沙箱，扫描和目标测试应由外部容器/VM 隔离。

## 安全与发布

漏洞报告方式见 [`SECURITY.md`](SECURITY.md)，贡献规则见 [`CONTRIBUTING.md`](CONTRIBUTING.md)，发布前检查见 [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md)。

仓库目前没有明确软件许可证。许可证是仓库所有者的法律选择；在许可证确定前，不应把代码视为已获开放源代码再分发授权。
