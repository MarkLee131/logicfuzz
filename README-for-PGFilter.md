# Part 1: How to run the logicfuzz project outside of Docker


## Step 1, set the API key for LLM (using DeepSeek as an example).
```
export DEEPSEEK_API_KEY="sk-e6d91a6015c54dadb13f1f056113ef48"
```



## Step 2: Run logicfuzz (using curl as an example).
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





# Part 2: How to run the logicfuzz project in Docker


```
cp logicfuzz.env.example logicfuzz.env
# Then edit logicfuzz.env and fill in DEEPSEEK_API_KEYY, LOGICFUZZ_MODEL, ENABLE_SOURCE_FILTER, SOURCE_FILTER_MIN_LINES, BENCHMARK_YAML etc.
```


```
docker run --rm   --network host   --env-file logicfuzz.env   -v /var/run/docker.sock:/var/run/docker.sock   -v "$PWD":/experiment   -w /experiment   logicfuzz   bash scripts/docker_run_experiment.sh
```






