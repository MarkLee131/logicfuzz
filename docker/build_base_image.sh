#!/bin/bash
# Build the custom base-builder-llvm14 image for LogicFuzz
#
# This image includes LLVM 14 and libc++ for bitcode extraction

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="logicfuzz/base-builder-llvm14"

echo "Building $IMAGE_NAME..."
docker build \
    -f "$SCRIPT_DIR/Dockerfile.base-builder-llvm14" \
    -t "$IMAGE_NAME" \
    "$SCRIPT_DIR"

echo ""
echo "Successfully built $IMAGE_NAME"
echo ""
echo "Verify with: docker run --rm $IMAGE_NAME clang-14 --version"
