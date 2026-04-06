#!/bin/bash
# Simple 24h fuzzing script using existing OSS-Fuzz infrastructure
# Usage: ./scripts/run_simple_fuzzing.sh <project> <duration_hours>

set -e

PROJECT=${1:-sqlite3}
DURATION_HOURS=${2:-24}
DURATION_SECS=$((DURATION_HOURS * 3600))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OSS_FUZZ_DIR="$PROJECT_ROOT/oss-fuzz"
RESULTS_DIR="$PROJECT_ROOT/results"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$RESULTS_DIR/extended_fuzzing/${PROJECT}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/run.log"
CORPUS_DIR="$OUTPUT_DIR/corpus"
CRASHES_DIR="$OUTPUT_DIR/crashes"
mkdir -p "$CORPUS_DIR" "$CRASHES_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting simple fuzzing for $PROJECT"
log "Duration: ${DURATION_HOURS}h (${DURATION_SECS}s)"
log "Output: $OUTPUT_DIR"

cd "$OSS_FUZZ_DIR"

# Build if needed (using existing cached images)
log "Building project (using cache if available)..."
python3 infra/helper.py build_image --no-pull "$PROJECT" >> "$LOG_FILE" 2>&1 || {
    log "ERROR: Failed to build image"
    exit 1
}

python3 infra/helper.py build_fuzzers --sanitizer address "$PROJECT" >> "$LOG_FILE" 2>&1 || {
    log "ERROR: Failed to build fuzzers"
    exit 1
}

# Find the fuzzer
FUZZER=$(ls build/out/${PROJECT}/*_fuzzer 2>/dev/null | head -1)
if [ -z "$FUZZER" ]; then
    FUZZER=$(ls build/out/${PROJECT}/*fuzzer 2>/dev/null | head -1)
fi
if [ -z "$FUZZER" ]; then
    log "ERROR: No fuzzer found in build/out/${PROJECT}/"
    exit 1
fi

FUZZER_NAME=$(basename "$FUZZER")
log "Using fuzzer: $FUZZER_NAME"

# Create seed corpus
for seed in "" "{}" "[]" '{"a":1}' "null" '"test"' "123" "true"; do
    echo -n "$seed" > "$CORPUS_DIR/seed_$(echo "$seed" | md5sum | cut -c1-8)"
done

# Run fuzzing
log "Starting fuzzer..."
python3 infra/helper.py run_fuzzer \
    --corpus-dir "$CORPUS_DIR" \
    "$PROJECT" "$FUZZER_NAME" \
    -- -max_total_time=$DURATION_SECS \
    -print_final_stats=1 \
    -detect_leaks=0 \
    -artifact_prefix="$CRASHES_DIR/" \
    >> "$LOG_FILE" 2>&1 &

FUZZER_PID=$!
log "Fuzzer PID: $FUZZER_PID"

# Wait for completion
wait $FUZZER_PID
EXIT_CODE=$?

log "Fuzzer exited with code: $EXIT_CODE"

# Build coverage version and measure
log "Measuring coverage..."
python3 infra/helper.py build_fuzzers --sanitizer coverage "$PROJECT" >> "$LOG_FILE" 2>&1 || {
    log "WARNING: Failed to build coverage fuzzers"
}

python3 infra/helper.py coverage \
    --corpus-dir "$CORPUS_DIR" \
    --fuzz-target "$FUZZER_NAME" \
    --no-serve --port "" \
    "$PROJECT" >> "$LOG_FILE" 2>&1 || {
    log "WARNING: Failed to measure coverage"
}

# Copy coverage report
if [ -d "build/out/${PROJECT}/report" ]; then
    cp -r "build/out/${PROJECT}/report" "$OUTPUT_DIR/coverage_report"
    log "Coverage report saved to $OUTPUT_DIR/coverage_report"
fi

# Parse final stats
log "=== FINAL STATS ==="
if [ -f "$OUTPUT_DIR/coverage_report/linux/summary.json" ]; then
    python3 -c "
import json
with open('$OUTPUT_DIR/coverage_report/linux/summary.json') as f:
    d = json.load(f)
t = d['data'][0]['totals']
print(f\"Lines: {t['lines']['covered']}/{t['lines']['count']} ({t['lines']['percent']:.1f}%)\")
print(f\"Branches: {t['branches']['covered']}/{t['branches']['count']} ({t['branches']['percent']:.1f}%)\")
print(f\"Functions: {t['functions']['covered']}/{t['functions']['count']} ({t['functions']['percent']:.1f}%)\")
" | tee -a "$LOG_FILE"
fi

# Count crashes
CRASH_COUNT=$(ls "$CRASHES_DIR"/crash-* 2>/dev/null | wc -l)
log "Unique crashes: $CRASH_COUNT"

# Count corpus
CORPUS_COUNT=$(ls "$CORPUS_DIR" 2>/dev/null | wc -l)
log "Final corpus size: $CORPUS_COUNT"

log "Done! Results in $OUTPUT_DIR"
