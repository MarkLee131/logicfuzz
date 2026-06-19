import os, glob, subprocess, pytest

@pytest.mark.skipif(os.environ.get("RUN_REFINE_INTEGRATION") != "1",
                    reason="LLM+pipeline; set RUN_REFINE_INTEGRATION=1")
def test_zlib_gz_drivers_materialize_input():
    subprocess.run("python3 run_logicfuzz.py -y comparison/zlib.yaml -l deepseek-v4-flash",
                   shell=True, timeout=3600, check=False)
    gz = [f for f in glob.glob("results/output-zlib-project/fuzz_targets/*.fuzz_target")
          if "gzopen" in open(f).read()]
    assert gz, "no gz* driver generated"
    # the refine-hole default materializes a file; the driver must no longer pass NULL/garbage
    assert any(("mkstemp" in open(f).read() or "fmemopen" in open(f).read()) for f in gz), \
        "gz* drivers still degenerate (no input-source materialization)"
