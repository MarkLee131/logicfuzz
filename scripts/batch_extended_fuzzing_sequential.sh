#!/bin/bash
# Sequential batch extended fuzzing script
# Run 24-hour fuzzing on high-quality drivers one by one
#
# Usage: nohup ./scripts/batch_extended_fuzzing_sequential.sh [duration_hours] &

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_ROOT/results"
OUTPUT_BASE="$RESULTS_DIR/extended_fuzzing"

# Duration in seconds (default 24 hours)
DURATION_HOURS=${1:-24}
DURATION_SECS=$((DURATION_HOURS * 3600))
SNAPSHOT_INTERVAL=1800  # 30 minutes

# Create output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$OUTPUT_BASE/run_${TIMESTAMP}"
mkdir -p "$RUN_DIR"

LOG_FILE="$RUN_DIR/batch_run.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting sequential batch extended fuzzing"
log "Duration per target: ${DURATION_HOURS}h (${DURATION_SECS}s)"
log "Output directory: $RUN_DIR"

# High-quality drivers to run (sorted by expected value)
TARGETS=(
    "sqlite3:05:$RESULTS_DIR/output-sqlite3-project/fuzz_targets/05.fuzz_target"
    "sqlite3:01:$RESULTS_DIR/output-sqlite3-project/fuzz_targets/01.fuzz_target"
    "re2:02:$RESULTS_DIR/output-re2-project/fuzz_targets/02.fuzz_target"
    "c-ares:02:$RESULTS_DIR/output-c-ares-project/fuzz_targets/02.fuzz_target"
)

TOTAL=${#TARGETS[@]}
COMPLETED=0
FAILED=0

for entry in "${TARGETS[@]}"; do
    IFS=':' read -r project target_id target_path <<< "$entry"
    target_name="${project}/${target_id}"

    if [ ! -f "$target_path" ]; then
        log "WARNING: Target not found: $target_path, skipping"
        continue
    fi

    output_dir="$RUN_DIR/${project}_${target_id}"
    target_log="$output_dir/run.log"
    mkdir -p "$output_dir"

    log "[$((COMPLETED+1))/$TOTAL] Starting: $target_name"
    log "  Target: $target_path"
    log "  Output: $output_dir"

    # Run synchronously
    if python3 "$SCRIPT_DIR/run_extended_fuzzing.py" \
        --project "$project" \
        --fuzz-target "$target_path" \
        --duration "$DURATION_SECS" \
        --output-dir "$output_dir" \
        --snapshot-interval "$SNAPSHOT_INTERVAL" \
        > "$target_log" 2>&1; then
        log "[$((COMPLETED+1))/$TOTAL] Completed: $target_name"
        COMPLETED=$((COMPLETED + 1))
    else
        log "[$((COMPLETED+1))/$TOTAL] FAILED: $target_name (exit code $?)"
        FAILED=$((FAILED + 1))
    fi

    # Brief pause between runs
    sleep 5
done

log "Batch run completed: $COMPLETED succeeded, $FAILED failed out of $TOTAL"

# Generate summary
log "Generating summary..."

cat > "$RUN_DIR/generate_summary.py" << 'PYTHON_SCRIPT'
import json
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
summary = {"targets": [], "total_branches": 0, "total_lines": 0, "total_crashes": 0}

for target_dir in sorted(run_dir.iterdir()):
    if not target_dir.is_dir() or target_dir.name.startswith('.'):
        continue
    results_file = target_dir / "results.json"
    if not results_file.exists():
        continue
    try:
        with open(results_file) as f:
            data = json.load(f)
        final_cov = data.get("final_coverage") or {}
        target_info = {
            "name": target_dir.name,
            "line_coverage_percent": final_cov.get("line_coverage_percent", 0),
            "branch_coverage_percent": final_cov.get("branch_coverage_percent", 0),
            "lines_covered": final_cov.get("lines_covered", 0),
            "lines_total": final_cov.get("lines_total", 0),
            "branches_covered": final_cov.get("branches_covered", 0),
            "branches_total": final_cov.get("branches_total", 0),
            "unique_crashes": data.get("unique_crashes", 0),
            "coverage_gain": data.get("total_coverage_gain", 0)
        }
        summary["targets"].append(target_info)
        summary["total_branches"] += target_info["branches_covered"]
        summary["total_lines"] += target_info["lines_covered"]
        summary["total_crashes"] += target_info["unique_crashes"]
    except Exception as e:
        print(f"Error processing {target_dir}: {e}")

print("\n" + "=" * 90)
print("BATCH FUZZING SUMMARY")
print("=" * 90)
print(f"{'Target':<15} {'Lines':<25} {'Branches':<25} {'Crashes':<10} {'Gain':<10}")
print("-" * 90)
for t in summary["targets"]:
    lines = f"{t['lines_covered']}/{t['lines_total']} ({t['line_coverage_percent']:.1f}%)"
    branches = f"{t['branches_covered']}/{t['branches_total']} ({t['branch_coverage_percent']:.1f}%)"
    print(f"{t['name']:<15} {lines:<25} {branches:<25} {t['unique_crashes']:<10} {t['coverage_gain']:+.2f}%")
print("-" * 90)
print(f"{'TOTAL':<15} {summary['total_lines']:<25} {summary['total_branches']:<25} {summary['total_crashes']}")
print("=" * 90)

with open(run_dir / "summary.json", 'w') as f:
    json.dump(summary, f, indent=2)
print(f"\nSummary saved to: {run_dir / 'summary.json'}")
PYTHON_SCRIPT

python3 "$RUN_DIR/generate_summary.py" "$RUN_DIR" | tee -a "$LOG_FILE"

log "All done!"
