# tests/test_extraction_integration.py
import json, os, subprocess, pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_EXTRACTION_INTEGRATION") != "1",
    reason="docker+SVF; set RUN_EXTRACTION_INTEGRATION=1 to run")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _run(project, env_extra=""):
    cmd = (f"LOGICFUZZ_NO_CACHE=1 PYTHONHASHSEED=0 {env_extra} "
           f"python3 scripts/measure_breadth.py comparison/{project}.yaml")
    subprocess.run(cmd, shell=True, cwd=REPO, timeout=24000, check=False)
    p = os.path.join(REPO, "results", project, "conditions.json")
    return p

@pytest.mark.parametrize("project", ["libpcap", "liblouis", "nghttp2", "sqlite3"])
def test_project_reaches_full(project):
    p = _run(project, "LIBERATOR_SVF_TIMEOUT_SECS=14400")
    assert os.path.exists(p), f"{project}: no conditions.json (still degraded)"
    assert len(json.load(open(p))) > 0, f"{project}: empty conditions"
