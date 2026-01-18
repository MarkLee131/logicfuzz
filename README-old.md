**LogicFuzz – Automated Fuzz Target Generation with Multi-Agent LLMs**

LogicFuzz uses AI agents to automatically generate, compile, and validate fuzz targets for C/C++ projects. The workflow is split into two phases: **Compilation** (make it build) and **Optimization** (run the fuzzer and validate crashes).

---

## 🚀 Quick Start

### 1. Prerequisites
- **Docker** (installed and running)
- **An LLM API key**, for example:
  - OpenAI (GPT‑4, GPT‑5)
  - Qwen via Alibaba Cloud DashScope (cost‑efficient)

(1) Virtual environment set up (No need if you use the Docker version of LogicFuzz)
```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

(2) LLM API key set up (No need if you use the Docker version of LogicFuzz)
```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Qwen (Singapore region)
export DASHSCOPE_API_KEY="sk-..."
export QWEN_BASE_URL="https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
```

You can obtain a Qwen API key from Alibaba Cloud Model Studio.

### Fuzz Introspector (required for CLI runs without Docker)

If you run LogicFuzz via the command-line (not using Docker), a local Fuzz Introspector web server must be available because some CLI workflows call its API (default port `8080`). You can either run Fuzz Introspector in Docker (no extra setup) or launch it locally using the helper scripts in `report/`:

- Start a quick local server using your local checkout (Recommended):
  ```bash
  bash report/launch_local_introspector.sh
  ```

- Or, start the server and build the database:
  ```bash
  bash report/launch_introspector.sh --source benchmark
  ```

Both scripts default to port `8080`. If the port is already in use, the scripts will warn; use `sudo lsof -i :8080` or `ss -ltnp | grep ':8080'` to check and free the port.

If you prefer Docker, run LogicFuzz inside the provided Docker setup — no local Fuzz Introspector process is required.

### 2. Minimal example
Generate fuzzers for the sample `cjson` benchmark:

```bash
python run_logicfuzz.py \
  -y conti-benchmark/curl.yaml \
  -n 1 \
  --model gpt-5.1
```

To use a different model:

```bash
python run_logicfuzz.py \
  -y conti-benchmark/curl.yaml \
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

## 📊 Viewing Results

After running LogicFuzz experiments, you can generate interactive HTML reports to visualize the results.

### Generate Static HTML Report

Generate a static HTML report from your experiment results:

```bash
python3 -m report.web
```

**Parameters:**
- `-r, --results-dir`: Directory containing LogicFuzz experiment results (default: `results`)
- `-o, --output-dir`: Output directory for the generated HTML report (default: `results-report`)
- `-b, --benchmark-set`: Benchmark set directory (optional, can be inferred from results)
- `-m, --model`: Model name (optional, can be inferred from results)
- `--with-csv, -csv`: Also generate a CSV file with the results (optional)
- `--base-url`: Base URL for serving the generated report (optional)

**Example:**
```bash
python3 -m report.web
```

The generated report can be viewed directly from the filesystem by opening `index.html` in your browser, or by hosting it with a web server.

---

## 📚 Documentation

| Guide | Description |
|-------|-------------|
| **`docs/RUNNING.md`** | How to run LogicFuzz (CLI flags, Docker usage, troubleshooting). |
| **`docs/NEW_PROJECT_SETUP.md`** | How to onboard new projects (OSS‑Fuzz, private repos, custom builds). |
| **`docs/WORKFLOW_DIAGRAM.md`** | High‑level workflow and architecture diagrams. |
| **`agent_graph/README.md`** | Implementation details of the LangGraph‑based agent workflow. |
