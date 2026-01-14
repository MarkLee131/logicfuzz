#!/bin/bash
#
# Bootstrap script for building the condition_extractor
#
set -e

echo "=== Building LogicFuzz Condition Extractor ==="
echo ""

# Source environment
if [ ! -f ./env.sh ]; then
    echo "Error: env.sh not found"
    exit 1
fi

source ./env.sh

# Set compiler flags
export CXXFLAGS="-Wno-deprecated-declarations -Wfatal-errors"

# Configure with CMake
echo "Configuring with CMake..."
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .

# Build
echo ""
echo "Building..."
make -j$(nproc)

echo ""
echo "✓ Build complete!"
echo "Extractor binary: ./bin/extractor"
