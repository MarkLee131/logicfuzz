# Environment Setup

How to set up host and container environments for LogicFuzz.

There are **two LLVM toolchains** in the system, and they must stay
on the **same major version** (currently **LLVM 14.0.6**):

| Toolchain | Where | Built / installed by | Used at |
|---|---|---|---|
| **Host LLVM-14 + SVF + Z3** | `$HOME/logicfuzz_deps/{llvm-14,SVF,z3}` | This guide | Build time of `condition_extractor` (statically linked) |
| **Container LLVM-14** | `/usr/lib/llvm-14` inside `logicfuzz/base-builder-llvm14` image | `docker/Dockerfile.base-builder-llvm14` | Runtime — `wllvm`/`clang-14` produces `.bc` for the extractor to read |

The two never coexist in one process; they communicate only through
the LLVM-14 bitcode (`.bc`) file. Once the host extractor is built it
no longer needs `logicfuzz_deps/` at runtime — the binary is statically
linked. `logicfuzz_deps/` is only needed if you rebuild `extractor`.

LLVM-14 was deliberately chosen because it predates opaque pointers;
LLVM ≥ 15 changes pointer representation and would require a synchronised
upgrade on both sides.

---

## Prerequisites

- Ubuntu/Debian Linux (the script also has a yum branch but is less tested)
- `sudo` for apt installs
- Docker (for the container image)
- ~8 GB disk under `$HOME/logicfuzz_deps`

---

## Quick install

```bash
# 1. Host-side deps (LLVM-14, SVF, Z3) -> $HOME/logicfuzz_deps
cd liberator_adapter
./setup_environment.sh

# 2. Build the host condition_extractor
cd liberator/condition_extractor
./bootstrap.sh
# binary at ./bin/extractor

# 3. Build the container base image
cd ../../../docker
./build_base_image.sh
```

To install host deps to a non-default location:
```bash
export LOGICFUZZ_DEPS_DIR=/path/to/custom/location
./setup_environment.sh
```

After this, the pipeline (`run_logicfuzz.py`) is ready to run.
You do **not** need `logicfuzz_deps/` on `PATH` or `LD_LIBRARY_PATH`
for normal pipeline use — the extractor is statically linked, and
`wllvm`/`clang-14` are invoked inside the container.

---

## What gets installed where

### Host: `$HOME/logicfuzz_deps/`

```
logicfuzz_deps/
├── llvm-14/                         # LLVM 14.0.6 (headers + libs + cmake configs)
│   ├── bin/llvm-config              # used by SVF + extractor build
│   ├── include/llvm/...
│   └── lib/cmake/llvm/...
├── SVF/                             # Source build, pinned commit
│   ├── Release-build/               # CMake build dir (or Debug-build)
│   ├── svf/include/
│   └── svf-llvm/include/
└── z3/                              # Pre-built binary release
    ├── bin/libz3.a, bin/z3
    └── include/z3.h
```

Pinned versions:

| Component | Version / commit | Source |
|---|---|---|
| LLVM | 14.0.6 (typed pointers) | apt or prebuilt tarball |
| SVF  | `f889cfbf7a4694183abbb3417f81887a44acab29` | https://github.com/SVF-tools/SVF |
| Z3   | 4.12.2 prebuilt (the script default; 4.8.x also works) | https://github.com/Z3Prover/z3/releases |

### Container: `logicfuzz/base-builder-llvm14`

Built from `docker/Dockerfile.base-builder-llvm14`. Extends the
OSS-Fuzz `base-builder` (Ubuntu 20.04) with:

- `clang-14`, `llvm-14`, `llvm-14-dev`, `llvm-14-tools`, `llvm-14-runtime`
- `libc++-14-dev`, `libc++abi-14-dev`, `libclang-14-dev`, `python3-clang-14`
- `wllvm` (via pip), with `LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin`
- libc++ symlinks under `/usr/lib/x86_64-linux-gnu/` so the linker
  finds them by default

Image references in code:
- `experiment/oss_fuzz_checkout.py:30` — `CUSTOM_BASE_BUILDER`
- `liberator_adapter/extractors/llvm_extractor.py:107` — pins
  container PATH to `/usr/lib/llvm-14/bin`

---

## Manual install (if you want to skip the helper script)

### LLVM 14

Either install via apt (recommended on Ubuntu 20.04) or unpack a
prebuilt tarball into `$HOME/logicfuzz_deps/llvm-14`:

```bash
# apt (lands in /usr/lib/llvm-14, env.sh detects it automatically)
sudo apt-get install -y llvm-14 llvm-14-dev clang-14

# OR prebuilt tarball
mkdir -p "$HOME/logicfuzz_deps"
cd "$HOME/logicfuzz_deps"
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/clang+llvm-14.0.6-x86_64-linux-gnu-ubuntu-18.04.tar.xz
tar xf clang+llvm-14.0.6-*.tar.xz
mv clang+llvm-14.0.6-* llvm-14
rm clang+llvm-14.0.6-*.tar.xz
```

### SVF

```bash
sudo apt-get install -y zlib1g-dev cmake gcc g++ ninja-build
mkdir -p "$HOME/logicfuzz_deps"
cd "$HOME/logicfuzz_deps"
git clone https://github.com/SVF-tools/SVF.git
cd SVF
git checkout f889cfbf7a4694183abbb3417f81887a44acab29

# Point SVF at the LLVM-14 you just installed
export LLVM_DIR=/usr/lib/llvm-14            # apt path
# OR  export LLVM_DIR=$HOME/logicfuzz_deps/llvm-14   # tarball path
./build.sh
# produces ./Release-build/
```

### Z3

```bash
cd "$HOME/logicfuzz_deps"
Z3_VER=4.12.2
wget "https://github.com/Z3Prover/z3/releases/download/z3-${Z3_VER}/z3-${Z3_VER}-x64-glibc-2.31.zip"
unzip -q "z3-${Z3_VER}-x64-glibc-2.31.zip"
mv "z3-${Z3_VER}-x64-glibc-2.31" z3
rm "z3-${Z3_VER}-x64-glibc-2.31.zip"
```

### Build the extractor

```bash
cd liberator_adapter/liberator/condition_extractor
source ./env.sh                       # sets SVF_DIR / Z3_DIR / LLVM_DIR
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .
make -j"$(nproc)"
./bin/extractor --version             # should print "Ubuntu LLVM version 14.0.6"
```

### Build the container image

```bash
cd docker
./build_base_image.sh
docker run --rm logicfuzz/base-builder-llvm14 clang-14 --version
# expected: "Ubuntu clang version 14.0.6"
```

---

## Environment variables (set by `env.sh`)

`liberator_adapter/liberator/condition_extractor/env.sh` resolves
paths in this order:

| Var | Resolution order |
|---|---|
| `SVF_DIR` | `$LOGICFUZZ_DEPS_DIR/SVF` (must contain `Release-build/` or `Debug-build/`) |
| `Z3_DIR`  | `$LOGICFUZZ_DEPS_DIR/z3` |
| `LLVM_DIR`| 1. `$LOGICFUZZ_DEPS_DIR/llvm-14.0.0.obj`<br>2. `/usr/lib/llvm-14`<br>3. fallback to whatever `llvm-config` finds |
| `LD_LIBRARY_PATH` | prepends `$Z3_DIR/bin` |
| `PATH` | prepends `$LLVM_DIR/bin`, then extractor `bin/` |

`LOGICFUZZ_DEPS_DIR` defaults to `$HOME/logicfuzz_deps`.

---

## Verifying the install

```bash
# Host LLVM (must be 14.x)
"$HOME/logicfuzz_deps/llvm-14/bin/llvm-config" --version  # 14.0.6

# Container LLVM (must match host major version)
docker run --rm logicfuzz/base-builder-llvm14 \
  /usr/lib/llvm-14/bin/llvm-config --version              # 14.0.6

# Extractor
./liberator_adapter/liberator/condition_extractor/bin/extractor --version
# Ubuntu LLVM version 14.0.6

# Run a tiny pipeline smoke test
python3 run_logicfuzz.py -y comparison/cjson.yaml --extract-only
```

---

## Troubleshooting

**`SVF build not found` from `env.sh`**
The script expects `$LOGICFUZZ_DEPS_DIR/SVF/Release-build/` (or
`Debug-build/`). Re-run `cd $HOME/logicfuzz_deps/SVF && ./build.sh`.

**`LLVM not found` from `env.sh`**
Install LLVM-14 via apt (`sudo apt-get install llvm-14 llvm-14-dev`)
or place a prebuilt LLVM-14 at `$HOME/logicfuzz_deps/llvm-14`.

**`libclang-cpp.so.14: cannot open shared object file`**
Only happens if you invoke `logicfuzz_deps/llvm-14/bin/clang` directly.
The pipeline never does this — bitcode is built inside the container
with `/usr/lib/llvm-14/bin/clang-14`. If you really need to run host
`clang`, prepend `$HOME/logicfuzz_deps/llvm-14/lib` to
`LD_LIBRARY_PATH`. (Some distros also need `libffi.so.7`; on Ubuntu
22.04+ symlink `libffi.so.8` to `libffi.so.7`.)

**Extractor rebuild keeps using old paths**
`liberator/condition_extractor/CMakeCache.txt` caches absolute paths
to `LLVM_DIR`, `SVF`, `Z3`. After moving `logicfuzz_deps`, delete
the cache before rebuilding:
```bash
cd liberator_adapter/liberator/condition_extractor
rm -rf CMakeCache.txt CMakeFiles bin
./bootstrap.sh
```

**Bitcode opaque-pointer errors from the extractor**
The container's clang-14 produced LLVM-15+ style bitcode. Make sure
the container image is `logicfuzz/base-builder-llvm14` (rebuild via
`docker/build_base_image.sh`) and that
`LLVM_COMPILER_PATH=/usr/lib/llvm-14/bin` is honoured (this is set
by `llvm_extractor.py:107`, but custom user-side wrappers can shadow it).

**Host and container LLVM major versions differ**
Both must be the same major version. Check:
```bash
"$HOME/logicfuzz_deps/llvm-14/bin/llvm-config" --version
docker run --rm logicfuzz/base-builder-llvm14 /usr/lib/llvm-14/bin/llvm-config --version
```
If they differ, either rebuild the container image (`build_base_image.sh`)
or replace the host LLVM and rebuild the extractor.

**Extractor cache is stale after rebuild**
Not a bug — `llvm_extractor.py` keys its cache on
`(bitcode_hash, extractor_binary_hash)` (see `_bitcode_fingerprint`).
A new extractor binary automatically invalidates entries.
