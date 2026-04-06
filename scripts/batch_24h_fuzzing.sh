#!/bin/bash
# Batch 24-hour fuzzing script for high-quality LogicFuzz drivers
# This runs all drivers sequentially, each for 24 hours
#
# Usage: ./scripts/batch_24h_fuzzing.sh [duration_hours]
#
# Default duration is 24 hours per driver

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_ROOT/results"

DURATION_HOURS=${1:-24}
DURATION_SECS=$((DURATION_HOURS * 3600))
SNAPSHOT_INTERVAL=3600  # 1 hour snapshots

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_BASE="$RESULTS_DIR/extended_fuzzing_${TIMESTAMP}"

LOG_FILE="$OUTPUT_BASE/batch_run.log"
mkdir -p "$OUTPUT_BASE"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting batch 24h fuzzing run"
log "Duration per driver: ${DURATION_HOURS}h (${DURATION_SECS}s)"
log "Output directory: $OUTPUT_BASE"

# High-quality drivers identified from previous analysis
# Format: "project:target_id:target_path"
declare -a TARGETS=(
    # sqlite3 drivers (>25% coverage in quick test)
    "sqlite3:05:$RESULTS_DIR/output-sqlite3-project/fuzz_targets/05.fuzz_target"
    "sqlite3:01:$RESULTS_DIR/output-sqlite3-project/fuzz_targets/01.fuzz_target"
    "sqlite3:03:$RESULTS_DIR/output-sqlite3-project/fuzz_targets/03.fuzz_target"
    "sqlite3:04:$RESULTS_DIR/output-sqlite3-project/fuzz_targets/04.fuzz_target"
    # re2 driver (24.6% coverage)
    "re2:02:$RESULTS_DIR/output-re2-project/fuzz_targets/02.fuzz_target"
    # c-ares drivers (5% coverage)
    "c-ares:02:$RESULTS_DIR/output-c-ares-project/fuzz_targets/02.fuzz_target"
    "c-ares:05:$RESULTS_DIR/output-c-ares-project/fuzz_targets/05.fuzz_target"
)

total_targets=${#TARGETS[@]}
current=0

for target_spec in "${TARGETS[@]}"; do
    IFS=':' read -r project target_id target_path <<< "$target_spec"
    current=$((current + 1))

    log "======================================"
    log "[$current/$total_targets] Starting: ${project} - ${target_id}"
    log "Target: $target_path"

    if [ ! -f "$target_path" ]; then
        log "WARNING: Target file not found, skipping: $target_path"
        continue
    fi

    output_dir="$OUTPUT_BASE/${project}_${target_id}"

    log "Running extended fuzzing..."
    python3 "$SCRIPT_DIR/run_extended_fuzzing_v2.py" \
        --project "$project" \
        --fuzz-target "$target_path" \
        --duration "$DURATION_SECS" \
        --output-dir "$output_dir" \
        --snapshot-interval "$SNAPSHOT_INTERVAL" \
        2>&1 | tee -a "$LOG_FILE" || {
            log "ERROR: Fuzzing failed for ${project}/${target_id}"
            continue
        }

    # Extract and log key metrics
    if [ -f "$output_dir/results.json" ]; then
        line_cov=$(python3 -c "import json; d=json.load(open('$output_dir/results.json')); print(f\"{d['final_coverage']['line_coverage_percent']:.2f}%\")")
        corpus_size=$(python3 -c "import json; d=json.load(open('$output_dir/results.json')); print(d['final_corpus_size'])")
        crashes=$(python3 -c "import json; d=json.load(open('$output_dir/results.json')); print(d['total_crashes'])")

        log "Results for ${project}/${target_id}:"
        log "  Line coverage: $line_cov"
        log "  Corpus size: $corpus_size"
        log "  Crashes: $crashes"
    fi

    log "Completed: ${project}/${target_id}"
done

log "======================================"
log "Batch fuzzing complete!"
log "Results saved in: $OUTPUT_BASE"

# Generate summary report
log "Generating summary report..."
python3 << 'SUMMARY_SCRIPT'
import json
import os
from pathlib import Path

output_base = os.environ.get('OUTPUT_BASE', '.')
results_dir = Path(output_base)

summary = {
    "total_targets": 0,
    "successful_targets": 0,
    "total_crashes": 0,
    "targets": []
}

for subdir in sorted(results_dir.iterdir()):
    if not subdir.is_dir():
        continue
    results_file = subdir / "results.json"
    if not results_file.exists():
        continue

    with open(results_file) as f:
        data = json.load(f)

    summary["total_targets"] += 1
    if data.get("error") is None:
        summary["successful_targets"] += 1

    summary["total_crashes"] += data.get("total_crashes", 0)

    summary["targets"].append({
        "name": subdir.name,
        "project": data.get("project"),
        "line_coverage": data.get("final_coverage", {}).get("line_coverage_percent", 0),
        "branch_coverage": data.get("final_coverage", {}).get("branch_coverage_percent", 0),
        "function_coverage": data.get("final_coverage", {}).get("function_coverage_percent", 0),
        "corpus_size": data.get("final_corpus_size", 0),
        "crashes": data.get("total_crashes", 0),
        "error": data.get("error"),
    })

with open(results_dir / "summary.json", "w") as f:
    json.dump(summary, f, indent=2)

print("\n=== SUMMARY ===")
print(f"Total targets: {summary['total_targets']}")
print(f"Successful: {summary['successful_targets']}")
print(f"Total crashes: {summary['total_crashes']}")
print("\nPer-target results:")
for t in summary["targets"]:
    status = "OK" if t["error"] is None else f"ERROR: {t['error']}"
    print(f"  {t['name']}: line={t['line_coverage']:.1f}%, branch={t['branch_coverage']:.1f}%, corpus={t['corpus_size']}, crashes={t['crashes']} [{status}]")
SUMMARY_SCRIPT

log "Done!"
