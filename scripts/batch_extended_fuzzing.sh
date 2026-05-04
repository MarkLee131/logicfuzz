#!/bin/bash
# Batch extended fuzzing script
# Run 24-hour fuzzing on all high-quality drivers
#
# Usage: ./scripts/batch_extended_fuzzing.sh [duration_hours]
# Default: 24 hours

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

log "Starting batch extended fuzzing"
log "Duration: ${DURATION_HOURS}h (${DURATION_SECS}s)"
log "Output directory: $RUN_DIR"

# Single-driver targets (one binary per row).
declare -A TARGETS=(
    ["c-ares/02"]="$RESULTS_DIR/output-c-ares-project/fuzz_targets/02.fuzz_target"
    ["c-ares/05"]="$RESULTS_DIR/output-c-ares-project/fuzz_targets/05.fuzz_target"
    ["re2/02"]="$RESULTS_DIR/output-re2-project/fuzz_targets/02.fuzz_target"
    ["sqlite3/01"]="$RESULTS_DIR/output-sqlite3-project/fuzz_targets/01.fuzz_target"
    ["sqlite3/03"]="$RESULTS_DIR/output-sqlite3-project/fuzz_targets/03.fuzz_target"
    ["sqlite3/04"]="$RESULTS_DIR/output-sqlite3-project/fuzz_targets/04.fuzz_target"
    ["sqlite3/05"]="$RESULTS_DIR/output-sqlite3-project/fuzz_targets/05.fuzz_target"
)

# Merged-harness targets (one fused binary per project — runs in parallel
# with the per-driver rows above). Set MERGED_PROJECTS to "" to skip.
# Each entry expects:
#   results/output-<proj>-project/merged/synthesized/  (from
#   `python -m tools.merge_drivers pipeline ...`)
MERGED_PROJECTS="${MERGED_PROJECTS:-c-ares sqlite3 re2}"

# Track PIDs for parallel runs
declare -A PIDS

# Run each target
for target_name in "${!TARGETS[@]}"; do
    target_path="${TARGETS[$target_name]}"
    project=$(echo "$target_name" | cut -d'/' -f1)
    target_id=$(echo "$target_name" | cut -d'/' -f2)

    if [ ! -f "$target_path" ]; then
        log "WARNING: Target not found: $target_path, skipping"
        continue
    fi

    output_dir="$RUN_DIR/${project}_${target_id}"
    target_log="$output_dir/run.log"
    mkdir -p "$output_dir"

    log "Starting: $target_name -> $output_dir"

    # Run in background
    python3 "$SCRIPT_DIR/run_extended_fuzzing.py" \
        --project "$project" \
        --fuzz-target "$target_path" \
        --duration "$DURATION_SECS" \
        --output-dir "$output_dir" \
        --snapshot-interval "$SNAPSHOT_INTERVAL" \
        > "$target_log" 2>&1 &

    PIDS["$target_name"]=$!
    log "Started PID ${PIDS[$target_name]} for $target_name"

    # Small delay between starts to avoid resource contention
    sleep 10
done

# Launch merged-harness fuzzing for each project that has a synthesized/
# directory ready. We don't auto-run `merge_drivers pipeline` here —
# that requires built per-driver binaries (see CLAUDE.md TODO). Caller
# should run the pipeline beforehand.
for proj in $MERGED_PROJECTS; do
    synth_dir="$RESULTS_DIR/output-${proj}-project/merged/synthesized"
    seed_dir="$RESULTS_DIR/output-${proj}-project/merged/corpus_merged"
    if [ ! -d "$synth_dir" ]; then
        log "WARNING: no synthesized harness for $proj at $synth_dir; skipping merged run"
        continue
    fi

    output_dir="$RUN_DIR/${proj}_merged"
    target_log="$output_dir/run.log"
    mkdir -p "$output_dir"

    log "Starting merged: $proj -> $output_dir (seeds=$seed_dir)"

    seed_arg=""
    if [ -d "$seed_dir" ]; then
        seed_arg="--seed-corpus-dir $seed_dir"
    fi

    python3 "$SCRIPT_DIR/run_extended_fuzzing.py" \
        --project "$proj" \
        --fuzz-target-dir "$synth_dir" \
        $seed_arg \
        --duration "$DURATION_SECS" \
        --output-dir "$output_dir" \
        --snapshot-interval "$SNAPSHOT_INTERVAL" \
        > "$target_log" 2>&1 &

    PIDS["${proj}_merged"]=$!
    log "Started PID ${PIDS[${proj}_merged]} for ${proj}_merged"
    sleep 10
done

log "All targets started. PIDs: ${PIDS[*]}"
log "Waiting for all targets to complete..."

# Save PID info for monitoring
echo "# Batch run started at $(date)" > "$RUN_DIR/pids.txt"
for target_name in "${!PIDS[@]}"; do
    echo "${PIDS[$target_name]} $target_name" >> "$RUN_DIR/pids.txt"
done

# Wait for all to complete
FAILED=0
for target_name in "${!PIDS[@]}"; do
    pid=${PIDS[$target_name]}
    if wait $pid; then
        log "Completed: $target_name (PID $pid)"
    else
        log "FAILED: $target_name (PID $pid) with exit code $?"
        FAILED=$((FAILED + 1))
    fi
done

log "Batch run completed. Failed: $FAILED/${#PIDS[@]}"

# Generate summary
log "Generating summary..."
python3 << 'EOF'
import json
import os
from pathlib import Path

run_dir = Path("$RUN_DIR".replace("$RUN_DIR", os.environ.get("RUN_DIR", ".")))
if not run_dir.exists():
    run_dir = Path(".")

summary = {
    "targets": [],
    "total_branches": 0,
    "total_lines": 0,
    "total_crashes": 0
}

for target_dir in sorted(run_dir.iterdir()):
    if not target_dir.is_dir() or target_dir.name.startswith('.'):
        continue

    results_file = target_dir / "results.json"
    if not results_file.exists():
        continue

    try:
        with open(results_file) as f:
            data = json.load(f)

        final_cov = data.get("final_coverage", {})
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

# Print summary table
print("\n" + "=" * 80)
print("BATCH FUZZING SUMMARY")
print("=" * 80)
print(f"{'Target':<20} {'Lines':<20} {'Branches':<20} {'Crashes':<10} {'Gain':<10}")
print("-" * 80)
for t in summary["targets"]:
    lines = f"{t['lines_covered']}/{t['lines_total']} ({t['line_coverage_percent']:.1f}%)"
    branches = f"{t['branches_covered']}/{t['branches_total']} ({t['branch_coverage_percent']:.1f}%)"
    print(f"{t['name']:<20} {lines:<20} {branches:<20} {t['unique_crashes']:<10} {t['coverage_gain']:+.2f}%")
print("-" * 80)
print(f"{'TOTAL':<20} {summary['total_lines']:<20} {summary['total_branches']:<20} {summary['total_crashes']}")
print("=" * 80)

# Save summary
summary_file = run_dir / "summary.json"
with open(summary_file, 'w') as f:
    json.dump(summary, f, indent=2)
print(f"\nSummary saved to: {summary_file}")
EOF

log "Done!"
