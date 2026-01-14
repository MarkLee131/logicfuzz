#!/bin/bash
#
# Environment setup for LogicFuzz condition_extractor
#
# This script sets up the required environment variables for building
# and running the condition_extractor with SVF, LLVM, and Z3.
#
# Updated to use source-built SVF (compatible with LLVM 14)
#

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECTHOME="$SCRIPT_DIR"

# Detect OS
sysOS=$(uname -s)

# Installation directory (default: $HOME/logicfuzz_deps)
INSTALL_DIR="${LOGICFUZZ_DEPS_DIR:-$HOME/logicfuzz_deps}"

echo "=== LogicFuzz Condition Extractor Environment ==="
echo "Project home: $PROJECTHOME"
echo "Dependencies: $INSTALL_DIR"
echo ""

#
# SVF Setup - Use source-built SVF (compatible with LLVM 14)
#
SVF_SOURCE_DIR="$INSTALL_DIR/SVF"
if [ -d "$SVF_SOURCE_DIR" ]; then
    # Check for Release-build or Debug-build
    if [ -d "$SVF_SOURCE_DIR/Release-build" ]; then
        export SVF_DIR="$SVF_SOURCE_DIR"
        echo "✓ SVF_DIR=$SVF_DIR (source build, Release)"
    elif [ -d "$SVF_SOURCE_DIR/Debug-build" ]; then
        export SVF_DIR="$SVF_SOURCE_DIR"
        echo "✓ SVF_DIR=$SVF_DIR (source build, Debug)"
    else
        echo "✗ SVF build not found. Please run:"
        echo "  cd $SVF_SOURCE_DIR && ./build.sh"
        return 1
    fi
else
    echo "✗ SVF source directory not found at $SVF_SOURCE_DIR"
    echo "  Please clone SVF and build it:"
    echo "  git clone https://github.com/SVF-tools/SVF.git $SVF_SOURCE_DIR"
    echo "  cd $SVF_SOURCE_DIR && git checkout f889cfbf7a4694183abbb3417f81887a44acab29"
    echo "  export LLVM_DIR=/usr/lib/llvm-14 && ./build.sh"
    return 1
fi

#
# Z3 Setup
#
if [ -d "$INSTALL_DIR/z3" ]; then
    export Z3_DIR="$INSTALL_DIR/z3"
    echo "✓ Z3_DIR=$Z3_DIR"
else
    echo "✗ Z3 not found at $INSTALL_DIR/z3"
    echo "  Run setup_environment.sh first"
    return 1
fi

#
# LLVM Setup
#
# Try to find LLVM in multiple locations:
# 1. Custom build in INSTALL_DIR
# 2. System LLVM via llvm-config
# 3. Common installation paths

if [ -d "$INSTALL_DIR/llvm-14.0.0.obj" ]; then
    # Custom LLVM build
    export LLVM_DIR="$INSTALL_DIR/llvm-14.0.0.obj"
    export PATH="$LLVM_DIR/bin:$PATH"
    echo "✓ LLVM_DIR=$LLVM_DIR (custom build)"
elif [ -d "/usr/lib/llvm-14" ]; then
    # System LLVM 14
    export LLVM_DIR="/usr/lib/llvm-14"
    export PATH="$LLVM_DIR/bin:$PATH"
    echo "✓ LLVM_DIR=$LLVM_DIR (system LLVM 14)"
elif command -v llvm-config &> /dev/null; then
    # System LLVM (generic)
    LLVM_VERSION=$(llvm-config --version | cut -d. -f1)
    export LLVM_DIR=$(llvm-config --prefix)
    export PATH="$LLVM_DIR/bin:$PATH"
    echo "✓ LLVM_DIR=$LLVM_DIR (system, version $LLVM_VERSION)"
else
    echo "✗ LLVM not found"
    echo "  Install LLVM: sudo apt-get install llvm-14 llvm-14-dev"
    return 1
fi

# Add project bin to PATH
export PATH="$PROJECTHOME/bin:$PATH"

# Add Z3 and SVF libraries to LD_LIBRARY_PATH
export LD_LIBRARY_PATH="$Z3_DIR/bin:$LD_LIBRARY_PATH"

echo ""
echo "Environment ready. You can now build the extractor:"
echo "  cd $PROJECTHOME && ./bootstrap.sh && make -j"
echo ""
