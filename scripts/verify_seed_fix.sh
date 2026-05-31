#!/bin/bash
# End-to-end verification of the merged-harness seed-routing fix.
# Generate c-ares ONCE, merge ONCE, then short-fuzz the SAME merged harness
# twice — tagging OFF (old verbatim) vs ON (fix) — and compare coverage.
# Only the seed-tagging differs, so any coverage delta is the fix's effect.
cd /home1/kaixuan/conti/fdg_2025/lf-refactor || exit 1
proj=c-ares
DUR=600   # 10 min per cell (short verification, not the 20h A/B)

echo "==== GENERATE $proj $(date +%H:%M:%S) ===="
rm -f results/$proj/static_analysis/skeleton_drivers.json results/$proj/comprehension/api_roles.json 2>/dev/null
rm -rf results/output-$proj-project 2>/dev/null
LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_DISABLE_BASELINE_RECOVERY=1 LLM_NUM_EXP=5 \
  .venv/bin/python3 run_logicfuzz.py -y comparison/$proj.yaml -l gpt-5-mini \
  > /tmp/vsf_gen.log 2>&1
echo "==== GENERATE done $(date +%H:%M:%S) drivers=$(ls results/output-$proj-project/fuzz_targets/[0-9]*.fuzz_target 2>/dev/null | wc -l) ===="

.venv/bin/python3 scripts/merge_compiled.py $proj > /tmp/vsf_merge.log 2>&1
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
