# OSS-Fuzz Build Script Generation (Core Library)

**⚠️ Note:** This is a **core library**, not a user-facing tool. For CLI usage, use the `oss-fuzz-generator` command instead.

## 🎯 Purpose

This module provides the core logic for automatically generating OSS-Fuzz build scripts (Dockerfile + build.sh + project.yaml) from GitHub repositories.

**What this library does:**
- Analyzes repository structure and build systems
- Generates Dockerfile with appropriate dependencies
- Creates build.sh with compilation commands
- Produces project.yaml with project metadata
- Creates empty fuzzer templates for harness generation

**What this library does NOT do:**
- Generate actual fuzz harnesses (handled by `agent_graph/`)
- Provide CLI interface (handled by `experimental/end_to_end/cli.py`)
- Fix build errors (handled by `experimental/build_fixer/`)

## 🏗️ Architecture

```
User Layer:
  oss-fuzz-generator CLI (experimental/end_to_end/cli.py)
          ↓
Core Library (This Module):
  experimental/build_generator/runner.py
          ↓
Components:
  ├── build_script_generator.py  - Generate build.sh
  ├── llm_agent.py              - LLM-based code generation
  ├── manager.py                - Orchestration logic
  └── templates.py              - Build script templates
```

## 📚 When to Use This Library

**Use this library directly IF:**
- You're developing new build generation features
- You need programmatic access to build generation
- You're integrating LogicFuzz into another tool

**Don't use this directly IF:**
- You just want to generate OSS-Fuzz projects → Use `oss-fuzz-generator generate-builds` instead
- You want the complete end-to-end pipeline → Use `oss-fuzz-generator generate-full` instead

---

This directory holds logic for generating build scripts for projects
from scratch. The goal is to automatically create OSS-Fuzz projects
given a set of repositories as input, and then use these generated
OSS-Fuzz projects as input to logicfuzz's core harness generation logic.

The projects generated contain an empty fuzzer that can be used by
OFG's core harness generation. As such, there is no focus here on
actually generating harnesses, however, there is focus on creating a
building and linking script that includes relevant target code.


## Usage

### ⭐ Recommended: Use the CLI Tool

```bash
# Install LogicFuzz CLI
python3 -m pip install .

# Use oss-fuzz-generator command (much easier!)
oss-fuzz-generator generate-builds \
  -m gpt-5 \
  -i input.txt \
  --oss-fuzz /path/to/oss-fuzz \
  -o generated-builds
```

See [experimental/end_to_end/README.md](../end_to_end/README.md) for full CLI documentation.

### 🔧 Advanced: Direct Library Usage

If you need programmatic access to this library:

```bash
cd logicfuzz
python3.11 -m virtualenv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt

git clone https://github.com/gejingquan/oss-fuzz

echo "https://github.com/gregjesl/simpleson" > input.txt

python3 -m experimental.build_generator.runner \
  -i input.txt \
  -o generated-builds-0 \
  -m ${MODEL} \
  --oss-fuzz oss-fuzz
```

**Output:**
```
generated-builds-0/
└── oss-fuzz-projects/
    └── simpleson-agent/
        ├── Dockerfile          # Auto-generated
        ├── build.sh           # Auto-generated
        ├── project.yaml       # Auto-generated
        └── empty_fuzzer.c     # Template for harness generation
```

The input file is a list of git repositories (one URL per line).

**Note:** There can be 0-to-many build setups per project. Each generated build may have
different characteristics, including the binary artifacts produced. This is, to some extent,
because it is impossible to know what the "real" artifacts should be, and each
project may be able to build in many different formats.

## 🔄 Integration with Full Pipeline

This library is one step in the complete end-to-end pipeline:

```
1. build_generator (this module)
   ↓ Generates: Dockerfile + build.sh + project.yaml
2. FuzzIntrospector database creation
   ↓ Analyzes: Project structure, functions, call graphs
3. run_logicfuzz.py
   ↓ Generates: Fuzz harnesses
4. Final output: Complete OSS-Fuzz project
```

To run the full pipeline, use: `oss-fuzz-generator generate-full`

## 📖 Related Documentation

- **CLI Tool:** [experimental/end_to_end/README.md](../end_to_end/README.md) - User-facing interface
- **Tool Overview:** [docs/TOOLS_OVERVIEW.md](../../docs/TOOLS_OVERVIEW.md) - Complete tool hierarchy
- **Build Fixing:** [experimental/build_fixer/](../build_fixer/) - Handles build errors