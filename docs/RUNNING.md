# Running LogicFuzz

This guide shows how to run LogicFuzz from the CLI and from Docker, plus a few common configurations.

## 🚀 Quick Start

### Prerequisites

1. **LLM API keys** (set at least one):

    ```bash
    # OpenAI (GPT‑4, GPT‑5)
    export OPENAI_API_KEY="sk-..."

    # DeepSeek
    export DEEPSEEK_API_KEY="sk-..."

    # Qwen (Alibaba Cloud DashScope)
    export DASHSCOPE_API_KEY="sk-..."
    # Optional: override API endpoint (default is Singapore region)
    export QWEN_BASE_URL="https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    ```

2. **Fuzz Introspector server** (optional but recommended):

    ```bash
    # Start FI in benchmark mode (default set = comparison)
    bash report/launch_introspector.sh --source benchmark --benchmark-set comparison
    ```

    You can also use `--source data-dir --data-dir <path>` when you already have a populated FI database.

### Basic CLI usage

Run LogicFuzz on all functions defined in a benchmark YAML:

```bash
python run_logicfuzz.py \
  -y conti-benchmark/curl.yaml \
  --model gpt-5
```

Key flags:
- `-y / --benchmark-yaml`: single benchmark YAML file.
- `-b / --benchmarks-directory`: directory with multiple benchmark YAML files.
- `--generate-benchmarks`: ask Fuzz Introspector to generate benchmark YAMLs automatically.

Exactly one of `--benchmark-yaml`, `--benchmarks-directory`, or `--generate-benchmarks` must be provided.

## 🐳 Docker deployment

LogicFuzz can also run fully in Docker for reproducibility.

### Build image

```bash
docker build -t logicfuzz:latest .
```

### Run experiments in Docker (split deployment)

Run Fuzz Introspector in its own container so LogicFuzz can be upgraded or restarted independently.  
This is the only supported Docker deployment mode (the runner container never launches FI itself).

1. Build image:

    ```bash
    docker build -f Dockerfile.fuzz-introspector -t logicfuzz-introspector .
    ```

2. Launch the FI server (benchmark mode):

    ```bash
    docker run --rm -p 8080:8080 \
      -v "$(pwd)"/conti-benchmark:/opt/logicfuzz/conti-benchmark \
      logicfuzz-introspector \
        --source benchmark
    ```

   Or reuse an existing data directory:

    ```bash
    docker run --rm -p 8080:8080 \
      -v /path/to/data-dir:/opt/logicfuzz/data-dir \
      logicfuzz-fi \
        --source data-dir \
        --data-dir data-dir
    ```

3. Point LogicFuzz to the running server (see `docs/DOCKER_SETUP.md` for the
   latest Docker‑based command). A typical local, non‑Docker example:

    ```bash
    python run_logicfuzz.py \
      -y conti-benchmark/cjson.yaml \
      --model gpt-5 \
      -e http://localhost:8080/api
    ```

#### docker compose example

```yaml
version: "3.9"
services:
  logicfuzz:
    build: .
    privileged: true
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    command:
      [
        "python3", "report/docker_run.py",
        "--local-introspector", "false",
        "-y", "conti-benchmark/curl.yaml",
        "--introspector-endpoint", "http://fuzz-introspector:8080/api",
        "--model", "gpt-5"
      ]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - .:/experiment
  fuzz-introspector:
    build:
      context: .
      dockerfile: Dockerfile.fuzz-introspector
    ports:
      - "8080:8080"
    volumes:
      - ./conti-benchmark:/opt/logicfuzz/conti-benchmark
      - ./data-dir:/opt/logicfuzz/data-dir
```

The compose file above is an example only—adjust benchmark/data directories and model arguments to match your workflow.

## 🔧 Common configuration flags

| Flag | Description | Typical value |
|------|-------------|---------------|
| `--model` | LLM model name | `gpt-5.1`, `qwen3-coder-plus`, etc. |
| `-e, --introspector-endpoint` | Fuzz Introspector API URL | `http://127.0.0.1:8080/api` or `http://0.0.0.0:8080/api` |
| `--num-samples` | Trials per function | 3–10 |
| `--temperature` | LLM sampling temperature | 0.3–0.5 |
| `--run-timeout` | Fuzzer runtime per trial (seconds) | 60–1800 |
| `-w, --work-dir` | Output directory for results | `./results` |

## 🌐 Using Qwen via OpenAI‑compatible API

LogicFuzz integrates Qwen models through Alibaba Cloud DashScope using the OpenAI‑compatible interface.

Basic setup:

```bash
export DASHSCOPE_API_KEY="sk-..."
export QWEN_BASE_URL="https://dashscope-intl.aliyuncs.com/compatible-mode/v1"  # Singapore (default)

python run_logicfuzz.py \
  -y conti-benchmark/curl.yaml \
  --model qwen3 \
  --num-samples 5
```

Qwen variants you can use:
- `qwen-turbo`: fast, cost‑effective.
- `qwen-plus`: long context, good quality.
- `qwen-max`: highest quality.
- `qwen3`: balanced default.

## 🐛 Troubleshooting (quick checklist)

- **Compilation fails repeatedly**
  - Check the project builds under OSS‑Fuzz.
  - Verify function signatures in the benchmark YAML.
  - Inspect `results/output-*/build_log.txt`.

- **Target function is not called**
  - Ensure the function name in YAML matches the actual code.
  - Check whether the function is internal/static.

- **No crashes found**
  - Increase `--run-timeout`.
  - Increase `--num-samples`.

