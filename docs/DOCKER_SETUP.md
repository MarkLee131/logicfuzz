# Docker Environment Quickstart

This guide shows how to run LogicFuzz entirely inside Docker. Two images are provided:

1. `Dockerfile` &rarr; LogicFuzz experiment runner (`report/docker_run.py` wrapper).
2. `Dockerfile.fuzz-introspector` &rarr; stand‑alone Fuzz Introspector service.

## 1. Prerequisites
- Docker Engine/ Docker Desktop (24+ recommended).  
  - Linux: https://docs.docker.com/engine/install/
  - macOS / Windows: install Docker Desktop and keep it running.
- A cloned LogicFuzz repository.
- Export at least one LLM API key (OpenAI, Qwen/DashScope, Vertex AI, etc.).

## 2. Build the runner image
```bash
docker build -t logicfuzz -f Dockerfile .
```
The image ships with a virtualenv in `/venv` and copies the entire tree under `/experiment`. Pass `INSTALL_HOST_CLI=false` when you do not need the bundled Docker/gcloud tooling.

If you prefer a single command end‑to‑end setup, you can use the helper script:

```bash
bash scripts/docker_quickstart.sh
```

This script:
- Builds both `logicfuzz` (runner) and `logicfuzz-introspector` images.
- Starts a Fuzz Introspector container on port 8080.
- Runs one LogicFuzz experiment against `conti-benchmark/cjson.yaml` using the model specified via `LOGICFUZZ_MODEL` (default: `qwen3-coder-plus`).

## 3. Run experiments inside the container
`report/docker_run.py` is a thin wrapper around `run_logicfuzz.py`. It expects an already running Fuzz Introspector service (started from a separate container) and executes the workflow. Reports remain as raw artifacts under `results/` and can be visualized later with `python -m report.web`.

```bash
# 1) Configure your LLM API keys following the example config file

cp logicfuzz.env.example logicfuzz.env

# Then edit logicfuzz.env and fill in DASHSCOPE_API_KEY / OPENAI_API_KEY, etc.


# 2) Start Fuzz Introspector in a background Docker container (one-time)
bash scripts/start_fi_docker.sh

# 3) Prepare a results directory for this run
WORK_DIR="results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$WORK_DIR"

# 4) Launch LogicFuzz in a separate container, passing env from logicfuzz.env.
#    Most options are preset in scripts/docker_run_experiment.sh; override via
#    LOGICFUZZ_MODEL, BENCHMARK_YAML, WORK_DIR, etc. if needed.
docker run --rm \
  --privileged \
  --network host \
  --env-file logicfuzz.env \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD":/experiment \
  -w /experiment \
  logicfuzz \
  bash scripts/docker_run_experiment.sh
```
  
> `--privileged` is needed because LogicFuzz spawns nested Docker builds

Key facts:
- The repo must be mounted at `/experiment`; results are written to `/experiment/results/*` so they persist on the host.
- If you omit `-y/--benchmark-yaml`, `-b/--benchmarks-directory`, and `-g/--generate-benchmarks`, the wrapper auto-selects `conti-benchmark` by injecting `-b conti-benchmark` before invoking `run_logicfuzz.py`, and `run_logicfuzz.py` will recursively load all YAMLs under that directory.
- Always point `--introspector-endpoint` (`-e`) to the external FI service started from a separate container (using the same `logicfuzz` image).
- Add `--redirect-outs true` to tee stdout/stderr into `results/logs-from-run.txt`.

## 4. Using the "data-dir" workflow (non OSS-Fuzz projects)

When `/experiment/data-dir` exists (or `/experiment/data-dir.zip` is mounted), the container automatically switches to `run_on_data_from_scratch()` mode. This is the recommended way to test custom projects that are **not in the upstream OSS-Fuzz repository**.

### When to Use data-dir Workflow

✅ Use this mode when:
- Your project is not in the upstream OSS-Fuzz repository
- You want to maintain your own OSS-Fuzz clone with custom projects
- You need to use pre-built Fuzz Introspector databases
- You're working with private/internal projects

### Step 1: Prepare data-dir Structure

Create a `data-dir` directory with the following structure:

```bash
mkdir -p data-dir/oss-fuzz2/projects
mkdir -p data-dir/fuzz_introspector_db  # Optional but recommended
```

### Step 2: Set Up Your Custom OSS-Fuzz Clone

```bash
# Option A: Clone a fresh OSS-Fuzz and add your project
git clone --depth 1 https://github.com/gejingquan/oss-fuzz data-dir/oss-fuzz2
cp -r oss-fuzz/projects/my-project data-dir/oss-fuzz2/projects/

# Option B: Use your existing OSS-Fuzz clone
cp -r /path/to/your/oss-fuzz data-dir/oss-fuzz2
```

Your `data-dir` should contain:
- `oss-fuzz2/` &rarr; custom OSS-Fuzz clone with your projects
- `fuzz_introspector_db/` &rarr; prebuilt FI database (optional)

### Step 3: Mount data-dir and Run

```bash
# Mount data-dir when running LogicFuzz container
docker run --rm \
  --privileged \
  --network host \
  --env-file logicfuzz.env \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD":/experiment \
  -v "$PWD/data-dir":/experiment/data-dir \
  -w /experiment \
  logicfuzz \
  python run_logicfuzz.py \
    -y conti-benchmark/my-project.yaml \
    --model gpt-5 \
    -e http://127.0.0.1:8080/api
```

### Step 4: Start Fuzz Introspector with data-dir

Start a dedicated FI container using the same `data-dir`:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/data-dir":/opt/logicfuzz/data-dir \
  logicfuzz-introspector \
    --source data-dir \
    --data-dir data-dir
```

The FI service will expose `http://127.0.0.1:8080/api`.

### How It Works

1. When `/experiment/data-dir` is detected, LogicFuzz automatically:
   - Sets `OSS_FUZZ_DATA_DIR` environment variable to `/experiment/data-dir/oss-fuzz2`
   - Switches to `run_on_data_from_scratch()` mode
   - Discovers all projects in `data-dir/oss-fuzz2/projects/`

2. The wrapper calls `run_logicfuzz.py -g ...` against the FI endpoint with heuristics:
   - `far-reach-low-coverage`
   - `low-cov-with-fuzz-keyword`
   - `easy-params-far-reach`

3. Reports are labeled `<date>-<benchmark_label>` and can be visualized with `python -m report.web`

### Alternative: Using CLI with Environment Variable

You can also use the data-dir workflow without Docker:

```bash
# Set environment variable
export OSS_FUZZ_DATA_DIR=/path/to/logic-fuzz/data-dir/oss-fuzz2

# Run LogicFuzz normally
python run_logicfuzz.py \
  -y conti-benchmark/my-project.yaml \
  --model gpt-5 \
  -e http://127.0.0.1:8080/api
```

### Complete Example

```bash
# 1. Prepare data-dir
mkdir -p data-dir/oss-fuzz2/projects
git clone --depth 1 https://github.com/gejingquan/oss-fuzz data-dir/oss-fuzz2
cp -r oss-fuzz/projects/my-project data-dir/oss-fuzz2/projects/

# 2. Start FI server
docker run -d --name fi-server -p 8080:8080 \
  -v "$PWD/data-dir":/opt/logicfuzz/data-dir \
  logicfuzz-introspector \
    --source data-dir --data-dir data-dir

# 3. Run LogicFuzz
docker run --rm --privileged --network host \
  --env-file logicfuzz.env \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD":/experiment \
  -v "$PWD/data-dir":/experiment/data-dir \
  -w /experiment \
  logicfuzz \
  python run_logicfuzz.py \
    -y conti-benchmark/my-project.yaml \
    --model gpt-5 \
    -e http://127.0.0.1:8080/api

# 4. Cleanup
docker stop fi-server && docker rm fi-server
```

For more details on setting up custom projects, see [`docs/NEW_PROJECT_SETUP.md`](NEW_PROJECT_SETUP.md#method-4-using-data-dir-workflow-recommended-for-custom-projects).

## 5. Verifying outputs
- Experiment artifacts: `results/output-*/` (on host because of the bind mount).
- HTML reports: run `python -m report.web -r results -b <benchmark_set> -m <model> -o report/html-report/<label>/` when you need them.
- FI service health: curl `http://127.0.0.1:8080/api/healthz`.

If the runner container exits with a non-zero status, inspect `results/logs-from-run.txt` (when `--redirect-outs true`) or the host terminal output. Since Docker uses your host Docker daemon through `/var/run/docker.sock`, make sure Docker Desktop/Engine is running before launching LogicFuzz.