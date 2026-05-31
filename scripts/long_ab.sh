#!/bin/bash
# Long-fuzz A/B for #2 (subsystem-balance): c-ares + lcms, each OFF/ON, 4h/cell.
# Per cell: regenerate portfolio (flag differs), merge compiled-only drivers,
# long-fuzz with the project's real seeds, snapshot coverage. ~20h total.
cd /home1/kaixuan/conti/fdg_2025/logic-fuzz || exit 1
DUR=14400   # 4 hours

for proj in c-ares lcms; do
  for mode in OFF ON; do
    flag=""
    [ "$mode" = "ON" ] && flag="1"
    tag="${proj}_${mode}"
    echo "==== [$tag] GENERATE start $(date +%H:%M:%S) ===="
    rm -f results/$proj/static_analysis/skeleton_drivers.json results/$proj/comprehension/api_roles.json 2>/dev/null
    rm -rf results/output-$proj-project 2>/dev/null
    LOGICFUZZ_NO_CACHE=1 LOGICFUZZ_DISABLE_BASELINE_RECOVERY=1 LOGICFUZZ_SUBSYS_BALANCE=$flag LLM_NUM_EXP=5 \
      .venv/bin/python3 run_logicfuzz.py -y comparison/$proj.yaml -l gpt-5-mini \
      > /tmp/longab_${tag}_gen.log 2>&1
    ndrv=$(ls results/output-$proj-project/fuzz_targets/[0-9]*.fuzz_target 2>/dev/null | wc -l)
    echo "==== [$tag] GENERATE done $(date +%H:%M:%S) drivers=$ndrv ===="

    .venv/bin/python3 scripts/merge_compiled.py $proj > /tmp/longab_${tag}_merge.log 2>&1
    cat /tmp/longab_${tag}_merge.log

    echo "==== [$tag] LONGFUZZ ${DUR}s start $(date +%H:%M:%S) ===="
    .venv/bin/python3 scripts/run_extended_fuzzing.py -p $proj \
      -f results/output-$proj-project/fuzz_targets/99.fuzz_target -d $DUR \
      > /tmp/longab_${tag}_fuzz.log 2>&1
    rm -rf /tmp/longab_cov_${tag}
    latest=$(ls -dt results/extended_fuzzing/$proj/*/ 2>/dev/null | head -1)
    cp -r "${latest}coverage" /tmp/longab_cov_${tag} 2>/dev/null
    fin=$(grep -E "Final:|Lines:" /tmp/longab_${tag}_fuzz.log | tail -2 | tr '\n' ' ')
    echo "==== [$tag] LONGFUZZ done $(date +%H:%M:%S)  $fin ===="
  done
done
echo "==== LONG A/B ALL DONE $(date +%H:%M:%S) ===="
