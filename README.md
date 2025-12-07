**LogicFuzz – Automated Fuzz Target Generation with Multi-Agent LLMs**

LogicFuzz uses AI agents to automatically generate, compile, and validate fuzz targets for C/C++ projects. The workflow is split into two phases: **Compilation** (make it build) and **Optimization** (run the fuzzer and validate crashes).

---

## 🚀 Quick Start

### 1. Prerequisites
- **Docker** (installed and running)
- **An LLM API key**, for example:
  - OpenAI (GPT‑4, GPT‑5)
  - Qwen via Alibaba Cloud DashScope (cost‑efficient)

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Qwen (Singapore region)
export DASHSCOPE_API_KEY="sk-..."
export QWEN_BASE_URL="https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
```

You can obtain a Qwen API key from Alibaba Cloud Model Studio.

### 2. Minimal example
Generate fuzzers for the sample `cjson` benchmark:

```bash
python run_logicfuzz.py \
  -y conti-benchmark/cjson.yaml \
  -n 1 \
  --model gpt-5.1
```

To use a different model:

```bash
python run_logicfuzz.py \
  -y conti-benchmark/cjson.yaml \
  -n 1 \
  --model qwen-plus
```

For more options (e.g., `--benchmarks-directory`, `--num-samples`, `--run-timeout`), see `docs/RUNNING.md`.

### 3. Available Models

| Model | Provider | Notes |
|-------|----------|-------|
| `qwen-max` | Alibaba Cloud | **Default**. Large context (258K tokens) |
| `qwen-plus` | Alibaba Cloud | Cost-efficient |
| `qwen3-coder-plus` | Alibaba Cloud | Optimized for code |
| `qwq-plus` | Alibaba Cloud | Reasoning model |
| `gpt-5` | OpenAI | |
| `gpt-5.1` | OpenAI | |
| `gpt-3.5-turbo` | OpenAI | |
| `deepseek-chat` | DeepSeek | Large context (128K tokens) |
| `deepseek-reasoner` | DeepSeek | Reasoning model |

List all available models with:

```bash
python run_logicfuzz.py --list-models
```

---

## 📚 Documentation

| Guide | Description |
|-------|-------------|
| **`docs/RUNNING.md`** | How to run LogicFuzz (CLI flags, Docker usage, troubleshooting). |
| **`docs/NEW_PROJECT_SETUP.md`** | How to onboard new projects (OSS‑Fuzz, private repos, custom builds). |
| **`docs/WORKFLOW_DIAGRAM.md`** | High‑level workflow and architecture diagrams. |
| **`agent_graph/README.md`** | Implementation details of the LangGraph‑based agent workflow. |
