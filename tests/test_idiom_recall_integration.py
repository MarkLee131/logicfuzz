import os, json, glob, subprocess, pytest

@pytest.mark.skipif(os.environ.get("RUN_RECALL_INTEGRATION") != "1",
                    reason="docker+LLM; set RUN_RECALL_INTEGRATION=1")
def test_zlib_gz_drivers_live_with_recall():
    # recall ON: expect ≥1 gz* skeleton flagged + at least one gz* driver generated
    subprocess.run("LOGICFUZZ_NO_CACHE=1 python3 run_logicfuzz.py -y comparison/zlib.yaml "
                   "-l deepseek-v4-flash --num-drivers 22", shell=True, timeout=5400, check=False)
    abl = json.load(open("results/zlib/recall_ablation.json"))
    assert abl["file_idiom_skeletons"] >= 1, abl
    gz = [f for f in glob.glob("results/output-zlib-project/fuzz_targets/*.fuzz_target")
          if "gzopen" in open(f).read()]
    assert gz, "no gz* driver generated with recall on"
    # at least one gz* driver writes fuzz bytes to a temp file (the idiom landed)
    assert any(("tmp" in open(f).read().lower() or "fopen" in open(f).read())
               for f in gz), "gz* drivers still degenerate (no tmpfile idiom)"
