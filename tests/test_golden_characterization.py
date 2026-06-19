"""Golden characterization tests — the safety net for behavior-preserving refactors.

Locks the EXACT gates-OFF behavior of the deterministic, LLM-free generation core
(construct_sequences + coverage-complete selection) for three representative
projects, from their cached offline artifacts (no docker, no LLM):

  lcms   — parser-heavy, many object-construction subsystems
  cjson  — chained-builder (the position-indexed-lifecycle case)
  c-ares — struct-handle library

Any refactor that changes the constructed sequences or the selected portfolio
under all gates OFF will fail these tests. To intentionally re-baseline after a
behavior change, delete the tests/golden/<project>.json file and re-run (capture
mode), then review the diff before committing.

REPRODUCIBILITY: the generation core has set/dict iteration that leaks Python's
per-process hash randomization into its output (different PYTHONHASHSEED ->
different sequence SET, not just order — a latent non-determinism bug). To make
this net reproducible regardless of how pytest is invoked, the snapshot is taken
in a SUBPROCESS pinned to PYTHONHASHSEED=0 (pytest cannot set it mid-process).
The underlying non-determinism is tracked separately as a refactor item.
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")
SNAPSHOT_SCRIPT = os.path.join(ROOT, "scripts", "_golden_snapshot.py")
PROJECTS = ["lcms", "cjson", "c-ares"]


def _has_artifacts(project):
    pa = os.path.join(ROOT, f"results/{project}/static_analysis/project_apis.json")
    return os.path.exists(pa)


def _snapshot(project):
    """Run the snapshot in a PYTHONHASHSEED=0 subprocess for reproducibility.

    Input is read from the FROZEN fixture tests/golden/<project>.input.json
    (seeded once from results/ in capture mode), so live runs that regenerate
    results/<project>/ cannot drift the golden's input.
    """
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = "0"
    for k in list(env):
        if k.startswith("LOGICFUZZ_"):
            del env[k]
    # Golden reflects gate-OFF baseline; explicitly disable so the default-ON
    # LOGICFUZZ_VALIDITY_CONTRACT does not alter the characterised behavior.
    env["LOGICFUZZ_VALIDITY_CONTRACT"] = "0"
    fixture = os.path.join(GOLDEN_DIR, f"{project}.input.json")
    out = subprocess.check_output(
        [sys.executable, SNAPSHOT_SCRIPT, project, fixture], env=env, cwd=ROOT)
    return json.loads(out)


@pytest.mark.parametrize("project", PROJECTS)
def test_generation_core_matches_golden(project):
    if not _has_artifacts(project):
        pytest.skip(f"no cached artifacts for {project}")
    snap = _snapshot(project)
    os.makedirs(GOLDEN_DIR, exist_ok=True)
    golden_path = os.path.join(GOLDEN_DIR, f"{project}.json")
    if not os.path.exists(golden_path):
        with open(golden_path, "w") as f:
            json.dump(snap, f, indent=2, sort_keys=True)
        pytest.skip(f"captured golden baseline for {project} "
                    f"(n_constructed={snap['n_constructed']}, "
                    f"n_selected={snap['n_selected']})")
    golden = json.load(open(golden_path))
    assert snap["n_constructed"] == golden["n_constructed"], (
        f"{project}: constructed count drifted "
        f"{golden['n_constructed']} -> {snap['n_constructed']}")
    assert snap["constructed"] == golden["constructed"], (
        f"{project}: constructed sequences drifted (gates-OFF behavior changed)")
    assert snap["n_selected"] == golden["n_selected"], (
        f"{project}: selected count drifted "
        f"{golden['n_selected']} -> {snap['n_selected']}")
    assert snap["selected"] == golden["selected"], (
        f"{project}: selected portfolio drifted (gates-OFF behavior changed)")
