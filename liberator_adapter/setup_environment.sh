#!/bin/bash
#
# Environment Setup Script for LogicFuzz Liberator Adapter
#
# This script installs the required dependencies for the condition_extractor:
# - SVF (Static Value-Flow Analysis framework)
# - LLVM 14 (optional, can use system LLVM)
# - Z3 (SMT solver)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Installation directory (default: $HOME/logicfuzz_deps)
INSTALL_DIR="${LOGICFUZZ_DEPS_DIR:-$HOME/logicfuzz_deps}"

echo -e "${GREEN}=== LogicFuzz Environment Setup ===${NC}"
echo "Installation directory: $INSTALL_DIR"
echo ""

# Create installation directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

#
# Step 1: Install system dependencies
#
echo -e "${YELLOW}[1/4] Installing system dependencies...${NC}"
if command -v apt-get &> /dev/null; then
    echo "Detected apt-get package manager"
    sudo apt-get update
    sudo apt-get install -y zlib1g-dev unzip cmake gcc g++ nodejs npm ninja-build
elif command -v yum &> /dev/null; then
    echo "Detected yum package manager"
    sudo yum install -y zlib-devel unzip cmake gcc gcc-c++ nodejs npm ninja-build
else
    echo -e "${RED}Warning: Could not detect package manager. Please install manually:${NC}"
    echo "  - zlib-dev, unzip, cmake, gcc, g++, nodejs, npm, ninja-build"
fi
echo -e "${GREEN}✓ System dependencies installed${NC}"
echo ""

#
# Step 2: Install SVF via npm
#
echo -e "${YELLOW}[2/4] Installing SVF...${NC}"
if [ ! -d "$INSTALL_DIR/node_modules/svf-lib" ]; then
    echo "Installing svf-lib via npm..."
    npm install --silent svf-lib --prefix "$INSTALL_DIR"
    echo -e "${GREEN}✓ SVF installed to $INSTALL_DIR/node_modules/svf-lib${NC}"
else
    echo -e "${GREEN}✓ SVF already installed${NC}"
fi
echo ""

#
# Step 3: Install Z3
#
echo -e "${YELLOW}[3/4] Installing Z3...${NC}"
if [ ! -d "$INSTALL_DIR/z3" ]; then
    echo "Downloading Z3..."
    Z3_VERSION="4.12.2"
    Z3_ARCHIVE="z3-${Z3_VERSION}-x64-glibc-2.31.zip"

    wget -q "https://github.com/Z3Prover/z3/releases/download/z3-${Z3_VERSION}/${Z3_ARCHIVE}"
    unzip -q "$Z3_ARCHIVE"
    mv "z3-${Z3_VERSION}-x64-glibc-2.31" z3
    rm "$Z3_ARCHIVE"

    echo -e "${GREEN}✓ Z3 installed to $INSTALL_DIR/z3${NC}"
else
    echo -e "${GREEN}✓ Z3 already installed${NC}"
fi
echo ""

#
# Step 4: LLVM (optional - can use system LLVM or compile from source)
#
echo -e "${YELLOW}[4/4] Checking LLVM...${NC}"
if command -v llvm-config &> /dev/null; then
    LLVM_VERSION=$(llvm-config --version)
    echo "Found system LLVM version: $LLVM_VERSION"
    echo -e "${GREEN}✓ Using system LLVM${NC}"
else
    echo -e "${YELLOW}Warning: LLVM not found in system${NC}"
    echo "You can:"
    echo "  1. Install LLVM via package manager: sudo apt-get install llvm-14 llvm-14-dev"
    echo "  2. Or compile from source (see install_llvm.sh in liberator directory)"
fi
echo ""

#
# Summary
#
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "Dependencies installed to: $INSTALL_DIR"
echo ""
echo "Next steps:"
echo "  1. Source the environment: source $SCRIPT_DIR/liberator/condition_extractor/env.sh"
echo "  2. Build the extractor: cd $SCRIPT_DIR/liberator/condition_extractor && ./bootstrap.sh"
echo ""
echo "Environment variables that will be set:"
echo "  SVF_DIR=$INSTALL_DIR/node_modules/svf-lib"
echo "  Z3_DIR=$INSTALL_DIR/z3"
echo "  LLVM_DIR=(system LLVM or custom build)"
echo ""
