"""One-off: re-measure lcms merged8 textcov over the saved 4h corpus and compute
the exact line-level coverage_diff vs the human OSS-Fuzz suite.

The extended-fuzzing harness saved summary.json + HTML but not the textcov
.covreport, so subtract_covered_lines (recall / WE_NEW / HUMAN_NEW) couldn't be
run from the run output. Here we rebuild the coverage binary, run OSS-Fuzz
`coverage` over the saved 1134-input corpus (which emits
textcov_reports/<target>.covreport), then diff against the human suite.
"""
import glob
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.getcwd())

from scripts.run_extended_fuzzing import ExtendedFuzzer  # noqa: E402
from scripts.cov_diff_dir import human  # noqa: E402
from experiment import textcov  # noqa: E402

SAVED_CORPUS = "results/extended_fuzzing/lcms/20260602_160254/corpus"
HUMAN_DATE = "20260530"


def main():
    ef = ExtendedFuzzer(
        project="lcms",
        fuzz_target_path=None,  # type: ignore[arg-type]  # drive fuzz_target_dir
        output_dir="/tmp/remeasure_merged8",
        fuzz_target_dir="results/output-lcms-project/merged8/synthesized",
        fuzzer_name="lcms_merged8",
        duration=0,
        snapshot_interval=300,
    )
    oss = ef._get_oss_fuzz_dir()
    helper = oss / "infra" / "helper.py"

    print("[1/5] setup project ...", flush=True)
    assert ef._setup_oss_fuzz_project(), "setup failed"
    print("[2/5] build address image ...", flush=True)
    assert ef._build_docker_image(), "address build failed"
    print("[3/5] build coverage image ...", flush=True)
    assert ef._build_coverage_image(), "coverage build failed"

    # Stage the saved 4h corpus (1134 inputs) as the measurement corpus.
    for f in ef.corpus_dir.glob("*"):
        if f.is_file():
            f.unlink()
    n = 0
    for src in glob.glob(f"{SAVED_CORPUS}/*"):
        if os.path.isfile(src):
            shutil.copy(src, ef.corpus_dir / os.path.basename(src))
            n += 1
    print(f"    staged {n} saved corpus inputs", flush=True)

    print("[4/5] run coverage (emits textcov) ...", flush=True)
    cmd = [
        "python3", str(helper), "coverage",
        "--corpus-dir", str(ef.corpus_dir.resolve()),
        "--fuzz-target", ef.target_name,
        "--no-serve", "--port", "",
        ef.coverage_project_name,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                       cwd=str(oss))
    print("    coverage rc:", r.returncode, flush=True)
    if r.returncode != 0:
        print(r.stderr[-2000:])

    assert ef.coverage_project_name
    build_out = oss / "build" / "out" / ef.coverage_project_name
    covreports = glob.glob(str(build_out / "textcov_reports" / "*.covreport"))
    print("    covreports:", covreports, flush=True)
    if not covreports:
        # fall back: search whole out dir
        covreports = glob.glob(str(build_out / "**" / "*.covreport"),
                               recursive=True)
        print("    covreports (deep):", covreports, flush=True)

    print("[5/5] compute coverage_diff vs human suite ...", flush=True)
    ours = textcov.Textcov()
    for f in covreports:
        with open(f, "rb") as fh:
            ours.merge(textcov.Textcov.from_file(fh))
    h = human("lcms", HUMAN_DATE)

    # Standard oss-fuzz-gen metric: copy both, subtract in place.
    import copy
    ours_c = copy.deepcopy(ours)
    ours_c.subtract_covered_lines(h)          # ours_c now = WE_NEW (ours - human)
    human_c = copy.deepcopy(h)
    human_c.subtract_covered_lines(ours)      # human_c now = HUMAN_NEW (human - ours)

    O = ours.covered_lines
    H = h.covered_lines
    WE_NEW = ours_c.covered_lines
    HUMAN_NEW = human_c.covered_lines
    inter = O - WE_NEW
    print("\n================ merged8 vs human (line-level) ================")
    print(f"OURS covered lines:   {O}")
    print(f"HUMAN union lines:    {H}")
    print(f"intersection:         {inter}")
    print(f"WE_NEW (ours-human):  {WE_NEW}")
    print(f"HUMAN_NEW (human-ours):{HUMAN_NEW}")
    print(f"recall (inter/human): {100*inter/H:.2f}%" if H else "n/a")
    print("==============================================================")

    ef._cleanup()


if __name__ == "__main__":
    main()
