#!/usr/bin/env bash

set -euo pipefail

# This script is intended to be run *inside* the logicfuzz Docker runner
# container at /experiment (see docs/DOCKER_SETUP.md).

MODEL="${LOGICFUZZ_MODEL:-qwen3-coder-plus}"
BENCHMARK_YAML="${BENCHMARK_YAML:-conti-benchmark/cjson.yaml}"
NUM_SAMPLES="${NUM_SAMPLES:-1}"
RUN_TIMEOUT="${RUN_TIMEOUT:-60}"
WORK_DIR="${WORK_DIR:-results/$(date +%Y%m%d-%H%M%S)}"
INTROSPECTOR_ENDPOINT="${INTROSPECTOR_ENDPOINT:-http://127.0.0.1:8080/api}"

mkdir -p "${WORK_DIR}"

echo "Running LogicFuzz with:"
echo "  MODEL                = ${MODEL}"
echo "  BENCHMARK_YAML       = ${BENCHMARK_YAML}"
echo "  NUM_SAMPLES          = ${NUM_SAMPLES}"
echo "  RUN_TIMEOUT          = ${RUN_TIMEOUT}"
echo "  WORK_DIR             = ${WORK_DIR}"
echo "  INTROSPECTOR_ENDPOINT= ${INTROSPECTOR_ENDPOINT}"

python3 report/docker_run.py \
  --redirect-outs true \
  --model "${MODEL}" \
  -y "${BENCHMARK_YAML}" \
  --work-dir "${WORK_DIR}" \
  --num-samples "${NUM_SAMPLES}" \
  --run-timeout "${RUN_TIMEOUT}" \
  --introspector-endpoint "${INTROSPECTOR_ENDPOINT}" \
  --context


