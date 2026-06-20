<p align="center">
  <h1 align="center">LogicFuzz</h1>
  <p align="center">
    <strong>Knowledge-Driven Neuro-Symbolic Fuzz Driver Generation over Structured API Program Spaces</strong>
  </p>
  <p align="center">
    <a href="#installation"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="License"></a>
    <a href="#supported-models"><img src="https://img.shields.io/badge/LLM-GPT%20%7C%20Claude%20%7C%20DeepSeek-purple.svg" alt="LLM Support"></a>
  </p>
</p>

---

LogicFuzz automatically generates high-quality fuzz drivers (harnesses) for C/C++ libraries by combining **static analysis**, **constraint solving (Z3)**, and **LLM-based agents** orchestrated via [LangGraph](https://github.com/langchain-ai/langgraph).

## Key Features

- **Reconcile-then-Construct** - Builds an `APISemanticModel` (IR ⊕ doc ⊕ usage), then constructs lifecycle-complete API sequences that are valid by construction (no repair stage)
- **Valid-by-Construction Binding** - Every non-nullable opaque-handle arg gets a type-matched producer with type-correct wiring; collection args are populated with real producer handles, never `{0}`/NULL (the *validity contract*, default-on)
- **Seed-Independent Drivers** - Scalar data-buffer args are rendered as `(T*)data` with a paired length bound to `size`, and a CREATOR's `FILE*`/path arg is materialized from the fuzzer bytes, so drivers exercise the library directly from the fuzz input
- **Breadth to the Extraction Ceiling** - A residual all-cover pass + greedy API-floor guarantees every public API the symbolic layer can reach appears in at least one driver
- **Multi-Agent Workflow** - Specialized agents for prototyping, compile-error fixing, and crash analysis (LangGraph)
- **Z3-Guided Synthesis** - Constraint-based driver generation with type matching, provenance tracking, and resource lifecycle management
- **Progressive Filter Pipeline** - layered filtering (L0–L4) from thousands of APIs down to high-value sequences
- **Automatic Error Recovery** - Intelligent error triage and iterative fixing with up to 3 retry attempts
- **Gap-Directed Construction** - Sequence construction and ranking are biased toward baseline-uncovered APIs (coverage-gap signal)
- **Portfolio Merge** - Folds successful trials into a single multi-task harness for breadth, behind a compile-validation gate (with optional single-shot LLM repair of non-compiling drivers)
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
              │ Extract APIs              │ Construct                 │ Fill holes
              │ Build dep graph           │ lifecycle-                │ Fix errors
              │ Analyze types             │ complete seqs             │ Analyze crashes
              ▼                           ▼                           ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                          Fuzz Driver Output                             │
    │                     (Ready for libFuzzer/AFL++)                         │
    └─────────────────────────────────────────────────────────────────────────┘
```

## Documentation

| Doc | What it covers |
|-----|----------------|
| `README.md` (this file) | User entry: what it is, install, quick-start, commands, supported projects, output. |
| `CLAUDE.md` | Agent operational guide: flag/gate reference, file/component map, design principles, implementation-flow steps, open TODOs, lessons, architecture map. |
| `docs/generation.md` | Driver-generation pipeline (G1–G5), handle-recovery, sequence construction, hole semantics, merge + coverage, build-cache, honest verdicts, roadmap. |
| `docs/knowledge_layer.md` | Comprehender + project-adaptive automaton mechanics. |
| `docs/contributions_and_related_work.md` | Innovations pitch + baseline comparison (PromeFuzz / Liberator) + per-LLM-call-site rationale. |

## Installation

### Prerequisites

- Python 3.10+
- Docker (for OSS-Fuzz build environment)
- API key for OpenAI or Anthropic

### Setup

```bash
# Clone the repository
git clone https://github.com/Marklee131/logicfuzz.git
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
python3 run_logicfuzz.py -y comparison/cjson.yaml -l claude-3-5-sonnet
```

### Step-by-Step Execution

```bash
# Step 1: Extract APIs only (no LLM calls)
python3 run_logicfuzz.py -y comparison/cjson.yaml --extract-only

# Step 2: Generate drivers with Z3-guided synthesis (static-only baseline, no LLM)
python3 run_logicfuzz.py -y comparison/cjson.yaml --generate-drivers --num-drivers 10

# Step 3: Run full pipeline with LLM agents
python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o
```

### Parallel Execution

```bash
# Run 5 experiments in parallel
LLM_NUM_EXP=5 python3 run_logicfuzz.py -y comparison/cjson.yaml -l gpt-4o
```

### Evaluation

```bash
# Fold successful trials into a single multi-task harness
python3 run_logicfuzz.py -y comparison/cjson.yaml --merge-drivers

# Closed-loop CBFactory feedback (re-synthesise with the grown automaton)
python3 run_logicfuzz.py -y comparison/cjson.yaml --closed-loop --closed-loop-iters 3

# Evaluation profile: bundles --closed-loop + --merge-drivers
python3 run_logicfuzz.py -y comparison/cjson.yaml --eval
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
| [lcms](comparison/lcms.yaml) | C | Little CMS color engine |
| [c-ares](comparison/c-ares.yaml) | C | Async DNS resolver |
| [mbedtls](comparison/mbedtls.yaml) | C | Crypto library |

## Architecture

LogicFuzz is **reconcile-then-construct**: static analysis builds an
`APISemanticModel` (IR ⊕ doc ⊕ usage), a sequence constructor builds
lifecycle-complete API chains from it, Z3 confirms the structure, and LLM agents
(Prototyper / Fixer / CrashAnalyzer, via LangGraph) fill only the typed holes.
A progressive filter (L0 type → L1 entry → L2 lifecycle → L3 state-machine → L4
reachability ranking → Top-K) supplies the grammar floor. See **`CLAUDE.md`** for
the component/architecture map and **`docs/generation.md`** for the full pipeline.

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
│   └── tools/                # Agent tools (Bash, GDB; introspector context is pre-fetched)
├── liberator_adapter/
│   ├── constraints/          # Filter pipeline (L0-L4)
│   └── driver/factory/       # Z3-guided synthesis
├── comparison/               # Project YAML configs
└── scripts/                  # Utility scripts
```


## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [OSS-Fuzz](https://github.com/google/oss-fuzz) - Google's continuous fuzzing infrastructure
