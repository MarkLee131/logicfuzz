# Part 1: How to run the logicfuzz project outside of Docker


## Step1: First, open terminal A and start the local Fuzz Introspector web server (in terminal A).

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
bash report/launch_local_introspector.sh
```



## Step 2, open terminal B and set up a virtual environment and install dependencies (in terminal B).

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```


## Step 3, set the API key for LLM (using DeepSeek as an example) (in terminal B).
```
export DEEPSEEK_API_KEY="sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```



## Step 4: Run logicfuzz (using curl as an example) (in terminal B).
```
python run_logicfuzz.py -y conti-benchmark/curl.yaml --model deepseek-chat -n 1 \
--enable-source-filter --source-filter-min-lines 10 \
--run-timeout 60 \
-e http://localhost:8080/api
```

## Explanation of each parameter is as follows:

| Short | Long | Argument | Description | Default |
|------|------|----------|-------------|---------|
| `-n` | `--num-samples` | `NUM_SAMPLES` | Number of samples to request from the LLM | — |
| `-y` | `--benchmark-yaml` | `BENCHMARK_YAML` | Path to a benchmark YAML file | — |
| `-to` | `--run-timeout` | `RUN_TIMEOUT` | Timeout (seconds) for each run | — |
| `-l` | `--model` | `MODEL` | LLM model to use (see supported models below) | — |
| `-e` | `--introspector-endpoint` | `INTROSPECTOR_ENDPOINT` | Endpoint for introspection service | — |
| — | `--enable-source-filter` | — | Enable PGFilter-based source code filtering | `false` |
| — | `--source-filter-min-lines` | `LINES` | Minimum function lines to trigger filtering | `50` |
| — | `--list-models` | — | List all available models and exit | — |



## Available Models

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

```
python run_logicfuzz.py --list-models
```


---

## Documentation

| Guide | Description |
|-------|-------------|
| **`docs/RUNNING.md`** | How to run LogicFuzz (CLI flags, Docker usage, troubleshooting). |
| **`docs/NEW_PROJECT_SETUP.md`** | How to onboard new projects (OSS‑Fuzz, private repos, custom builds). |
| **`docs/WORKFLOW_DIAGRAM.md`** | High‑level workflow and architecture diagrams. |
| **`agent_graph/README.md`** | Implementation details of the LangGraph‑based agent workflow. |



# Part 2: How to view the results

## Step 1: open terminal C and generate static HTML report (in terminal C)

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m report.web -r results -s
```





# Part 3: How to run the logicfuzz project in Docker

This part is still under debugging...



```bash
cp logicfuzz.env.example logicfuzz.env
# Then edit logicfuzz.env and fill in DEEPSEEK_API_KEYY, LOGICFUZZ_MODEL, ENABLE_SOURCE_FILTER, SOURCE_FILTER_MIN_LINES, BENCHMARK_YAML etc.
```


```
docker run --rm   --network host   --env-file logicfuzz.env   -v /var/run/docker.sock:/var/run/docker.sock   -v "$PWD":/experiment   -w /experiment   logicfuzz   bash scripts/docker_run_experiment.sh
```






