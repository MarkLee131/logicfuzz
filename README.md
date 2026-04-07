<p align="center">
  <h1 align="center">LogicFuzz</h1>
  <p align="center">
    <strong>LLM-Powered Agentic Fuzz Driver Generation for C/C++ Libraries</strong>
  </p>
  <p align="center">
    <a href="#installation"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="License"></a>
    <a href="#supported-models"><img src="https://img.shields.io/badge/LLM-GPT%20%7C%20DeepSeek-purple.svg" alt="LLM Support"></a>
  </p>
</p>

---

LogicFuzz automatically generates high-quality fuzz drivers (harnesses) for C/C++ libraries by combining **static analysis**, **constraint solving (Z3)**, and **LLM-based agents** orchestrated via [LangGraph](https://github.com/langchain-ai/langgraph).

## Key Features

- **Multi-Agent Workflow** - Specialized agents for prototyping, fixing, coverage analysis, crash analysis, and improvement
- **Z3-Guided Synthesis** - Constraint-based driver generation with type matching, provenance tracking, and resource lifecycle management
- **Progressive Filter Pipeline** - 6-layer filtering (L0-L5) from thousands of APIs down to high-value sequences
- **Automatic Error Recovery** - Intelligent error triage and iterative fixing with up to 3 retry attempts
- **Coverage-Aware Generation** - Prioritizes uncovered code paths and API combinations
- **OSS-Fuzz Integration** - Seamless integration with Google's OSS-Fuzz infrastructure

## How It Works

```
                    ┌─────────────────────────────────────────────────┐
                    │                 LogicFuzz Pipeline              │
                    └─────────────────────────────────────────────────┘
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              ▼                           ▼                           ▼
    ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
    │  Static Analysis │         │  Z3-Guided      │         │  LLM Agents     │
    │  (Liberator)     │         │  Synthesis      │         │  (LangGraph)    │
    └─────────────────┘         └─────────────────┘         └─────────────────┘
              │                           │                           │
              │ Extract APIs              │ Generate                  │ Prototype
              │ Build dep graph           │ sequences                 │ Fix errors
              │ Analyze types             │ with Z3                   │ Analyze coverage
              ▼                           ▼                           ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                          Fuzz Driver Output                             │
    │                     (Ready for libFuzzer/AFL++)                         │
    └─────────────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.10+
- Docker (for OSS-Fuzz build environment)
- API key for OpenAI or Anthropic

### Setup

```bash
# Clone the repository
git clone https://github.com/anthropics/logicfuzz.git
cd logicfuzz

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up API key
export OPENAI_API_KEY="your-key-here"
# or
export ANTHROPIC_API_KEY="your-key-here"
```

## Quick Start

### Basic Usage

```bash
# Generate fuzz drivers for cJSON library
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o

# Use Claude instead
python3 run_logicfuzz.py -y comparison/cjson.yaml -l claude-3-5-sonnet-20241022
```

### Step-by-Step Execution

```bash
# Step 1: Extract APIs only (no LLM calls)
python3 run_logicfuzz.py -y comparison/cjson.yaml --extract-only

# Step 2: Generate drivers with Z3-guided synthesis
python3 run_logicfuzz.py -y comparison/cjson.yaml --generate-drivers --num-drivers 10

# Step 3: Run full pipeline with LLM agents
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o
```

### Parallel Execution

```bash
# Run 5 experiments in parallel
LLM_NUM_EXP=5 python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o
```

## Configuration

Create a YAML file for your target library:

```yaml
language: "c"                    # c or c++
project: "mylib"                 # project name (must exist in OSS-Fuzz)
url: "https://github.com/org/mylib.git"
target_name: "mylib_fuzzer"      # existing fuzzer name for reference
target_path: "/src/mylib/fuzz/fuzzer.c"
```

See [`comparison/`](comparison/) for more examples.

## Supported Projects

LogicFuzz has been tested on these OSS-Fuzz projects:

| Project | Language | Description |
|---------|----------|-------------|
| [cJSON](comparison/cjson.yaml) | C | JSON parser |
| [re2](comparison/re2.yaml) | C++ | Regular expression engine |
| [sqlite3](comparison/sqlite3.yaml) | C | SQL database engine |
| [libucl](comparison/libucl.yaml) | C | Universal config library |
| [libaom](comparison/libaom.yaml) | C | AV1 codec |
| [zlib](comparison/zlib.yaml) | C | Compression library |
| [libpng](comparison/libpng.yaml) | C | PNG image library |
| [libtiff](comparison/libtiff.yaml) | C | TIFF image library |
| [curl](comparison/curl.yaml) | C | URL transfer library |
| [mbedtls](comparison/mbedtls.yaml) | C | Crypto library |

## Architecture

### Agent System

| Agent | Purpose |
|-------|---------|
| **Prototyper** | Generate initial fuzz driver from API sequence |
| **Fixer** | Fix compilation errors with error triage |
| **CoverageAnalyzer** | Diagnose low coverage, suggest improvements |
| **CrashAnalyzer** | Determine if crash is driver bug or real bug |
| **Improver** | Improve coverage based on analyzer suggestions |

### Filter Pipeline

```
All APIs → L0 Type → L1 Entry → L2 Lifecycle → L3 StateMachine → L4 Ranking → L5 Coverage → Top-K
 (1000+)   (~100)     (~50)       (~30)           (~15)           (K=12)        (prioritized)
```

| Layer | Constraint |
|-------|------------|
| **L0** | Type compatibility (`API_A.return_type == API_B.param_type`) |
| **L1** | Entry point detection (`uint8_t* data, size_t size`) |
| **L2** | Lifecycle pairing (`init` ↔ `destroy`) |
| **L3** | State machine validation (no use-after-destroy) |
| **L4** | Diversity ranking (greedy selection) |
| **L5** | Coverage-aware prioritization |

## Output

Generated fuzz drivers are saved to:

```
results/output-{project}-project/
├── fuzz_targets/
│   ├── 00.fuzz_target    # Generated drivers
│   ├── 01.fuzz_target
│   └── ...
├── coverage/             # Coverage reports
└── logs/                 # Execution logs
```

## Extended Fuzzing Evaluation

Run 24-hour fuzzing campaigns:

```bash
# Run extended fuzzing on a generated driver
python scripts/run_extended_fuzzing.py \
    -p re2 \
    -f results/output-re2-project/fuzz_targets/02.fuzz_target \
    -d 86400
```

## Development

```bash
# Code quality checks
pylint src/
pyright src/

# Format code
yapf -i -r src/
```

## Project Structure

```
logicfuzz/
├── run_logicfuzz.py          # Main entry point
├── src/
│   ├── agents/               # LLM agents (Prototyper, Fixer, etc.)
│   ├── context/              # FuzzingContext (SSOT)
│   ├── workflow/             # LangGraph workflow & supervisor
│   └── tools/                # Agent tools (FuzzIntrospector, Bash)
├── liberator_adapter/
│   ├── constraints/          # Filter pipeline (L1-L5)
│   └── driver/factory/       # Z3-guided synthesis
├── comparison/               # Project YAML configs
└── scripts/                  # Utility scripts
```

## Citation

If you use LogicFuzz in your research, please cite:

```bibtex
@software{logicfuzz2024,
  title = {LogicFuzz: LLM-Powered Agentic Fuzz Driver Generation},
  year = {2024},
  url = {https://github.com/anthropics/logicfuzz}
}
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [OSS-Fuzz](https://github.com/google/oss-fuzz) - Google's continuous fuzzing infrastructure
- [Fuzz Introspector](https://github.com/ossf/fuzz-introspector) - Static analysis for fuzzing
- [LangGraph](https://github.com/langchain-ai/langgraph) - Agent orchestration framework
