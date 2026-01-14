# Environment Setup for LogicFuzz Liberator Adapter

This document explains how to set up the environment for building and running the condition_extractor with provenance tracking support.

## Prerequisites

- Ubuntu/Debian Linux (or similar)
- sudo access for installing system packages
- Internet connection for downloading dependencies

## Quick Start

### 1. Install Dependencies

Run the main setup script to install SVF, Z3, and optionally LLVM:

```bash
cd /home/likaixuan/fuzzing/logicfuzz/liberator_adapter
./setup_environment.sh
```

This will install:
- **SVF** (Static Value-Flow Analysis) via npm
- **Z3** (SMT solver) from GitHub releases
- System dependencies (cmake, gcc, nodejs, etc.)

By default, dependencies are installed to `$HOME/logicfuzz_deps`. You can customize this by setting the `LOGICFUZZ_DEPS_DIR` environment variable:

```bash
export LOGICFUZZ_DEPS_DIR=/path/to/custom/location
./setup_environment.sh
```

### 2. Build the Condition Extractor

```bash
cd liberator/condition_extractor
./bootstrap.sh
```

This will:
- Source the environment (env.sh)
- Configure with CMake
- Build the extractor

The compiled binary will be at: `./bin/extractor`

## Manual Setup

If you prefer to install dependencies manually:

### Install System Packages

```bash
sudo apt-get update
sudo apt-get install -y zlib1g-dev unzip cmake gcc g++ nodejs npm ninja-build llvm-14 llvm-14-dev
```

### Install SVF

```bash
npm install --silent svf-lib --prefix $HOME/logicfuzz_deps
```

### Install Z3

```bash
cd $HOME/logicfuzz_deps
wget https://github.com/Z3Prover/z3/releases/download/z3-4.12.2/z3-4.12.2-x64-glibc-2.31.zip
unzip z3-4.12.2-x64-glibc-2.31.zip
mv z3-4.12.2-x64-glibc-2.31 z3
```

### Build Extractor

```bash
cd liberator/condition_extractor
source ./env.sh
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .
make -j$(nproc)
```

## Environment Variables

The `env.sh` script sets up the following environment variables:

- `SVF_DIR`: Path to SVF installation
- `Z3_DIR`: Path to Z3 installation
- `LLVM_DIR`: Path to LLVM installation
- `PATH`: Updated to include LLVM and extractor binaries

## Troubleshooting

### SVF not found

If you see "SVF not found", ensure you ran `setup_environment.sh` first and that npm successfully installed svf-lib.

### Z3 not found

Download Z3 manually from https://github.com/Z3Prover/z3/releases and extract to `$HOME/logicfuzz_deps/z3`.

### LLVM not found

Install system LLVM:
```bash
sudo apt-get install llvm-14 llvm-14-dev
```

Or compile from source (see liberator's `install_llvm.sh` and `bootstrap_llvm.sh`).

### Build errors

Check that all environment variables are set correctly:
```bash
source ./env.sh
echo $SVF_DIR
echo $Z3_DIR
echo $LLVM_DIR
```

## Verifying the Installation

After building, verify the extractor works:

```bash
./bin/extractor --help
```

You should see the extractor's usage information.

## Next Steps

After successful setup:
1. Run the extractor on a test project
2. Verify provenance information is extracted
3. Test the Python-side dependency graph filtering

See the main project README for usage examples.
