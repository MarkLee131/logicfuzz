#!/bin/bash
# A/B one cell: regen+merge with a gate, build+fuzz, report merged cov + crashes.
# usage: ab_gate_cell.sh <project> <label> [GATE=val ...]
set -u
PROJ="$1"; LABEL="$2"; shift 2
OUT="results/extended_fuzzing/ab_${PROJ}_${LABEL}"
LOG="/tmp/ab_${PROJ}_${LABEL}.log"
echo "[$(date '+%H:%M:%S')] CELL $PROJ/$LABEL gates: $*"
# 1) regen + merge with the gate(s)
env LOGICFUZZ_NO_CACHE=1 "$@" python3 run_logicfuzz.py -y "comparison/${PROJ}.yaml" --merge-drivers > "$LOG" 2>&1
NDRV=$(ls results/output-${PROJ}-project/merged/synthesized/*.c* 2>/dev/null | grep -v entry | wc -l)
echo "[$(date '+%H:%M:%S')]   regen+merge done: $NDRV sub-drivers"
# 2) build + 10min fuzz
env "$@" python3 scripts/run_extended_fuzzing.py --project "$PROJ" \
  --fuzz-target-dir results/output-${PROJ}-project/merged/synthesized \
  --duration 1800 --snapshot-interval 1800 --output-dir "$OUT" >> "$LOG" 2>&1
# 3) extract cov + crashes
STAT=$(grep -oE "cov: [0-9]+ ft: [0-9]+ .*crash: [0-9/]+" "$OUT/logs/fuzzer.log" 2>/dev/null | tail -1)
echo "[$(date '+%H:%M:%S')]   RESULT $PROJ/$LABEL: drivers=$NDRV | $STAT"
echo "RESULT $PROJ $LABEL drivers=$NDRV $STAT" >> /tmp/ab_results.txt
