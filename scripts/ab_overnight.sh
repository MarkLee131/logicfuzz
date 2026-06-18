#!/bin/bash
set -u
cd "$(dirname "$0")/.."
: > /tmp/ab_results.txt
echo "[$(date '+%F %H:%M')] OVERNIGHT A/B START" | tee -a /tmp/ab_results.txt
for proj in cjson lcms; do
  bash scripts/ab_gate_cell.sh "$proj" off
  bash scripts/ab_gate_cell.sh "$proj" apifloor  LOGICFUZZ_API_FLOOR=1
  bash scripts/ab_gate_cell.sh "$proj" objconstruct LOGICFUZZ_OBJCONSTRUCT_FIRST=1
done
echo "[$(date '+%F %H:%M')] OVERNIGHT A/B DONE" | tee -a /tmp/ab_results.txt
