#!/bin/bash
# Fast variant: REUSE the already-generated c-ares drivers (gen is the slow part,
# ~1h; it's idempotent for this purpose). Merge compiled-only → short-fuzz the
# SAME merged harness twice (tagging OFF=verbatim vs ON=fix). Only the seed
# tagging differs, so any coverage delta is the seed-routing fix's effect.
cd /home1/kaixuan/conti/fdg_2025/logic-fuzz || exit 1
proj=c-ares
DUR=600   # 10 min per cell

ndrv=$(ls results/output-$proj-project/fuzz_targets/[0-9]*.fuzz_target 2>/dev/null | wc -l)
echo "==== REUSE $ndrv existing $proj drivers $(date +%H:%M:%S) ===="
if [ "$ndrv" -lt 2 ]; then
  echo "ERROR: need >=2 existing drivers; run full verify_seed_fix.sh first"; exit 1
fi

PYTHONPATH=. .venv/bin/python3 scripts/merge_compiled.py $proj > /tmp/vsf_merge.log 2>&1
cat /tmp/vsf_merge.log
cp results/output-$proj-project/fuzz_targets/99.fuzz_target /tmp/vsf_merged99.fuzz_target

for mode in OFF ON; do
  dis=""
  [ "$mode" = "OFF" ] && dis="1"
  echo "==== FUZZ tagging=$mode ${DUR}s $(date +%H:%M:%S) ===="
  LOGICFUZZ_DISABLE_SEED_TAGGING=$dis \
    .venv/bin/python3 scripts/run_extended_fuzzing.py -p $proj \
    -f /tmp/vsf_merged99.fuzz_target -d $DUR > /tmp/vsf_fuzz_${mode}.log 2>&1
  fin=$(grep -E "Final:|Lines:|Seeded corpus" /tmp/vsf_fuzz_${mode}.log | tail -3 | tr '\n' ' ')
  echo "==== FUZZ tagging=$mode done $(date +%H:%M:%S)  $fin ===="
done
echo "==== VERIFY DONE $(date +%H:%M:%S) ===="
