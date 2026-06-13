import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.merge_drivers import compile_validate as cv


def test_validate_sh_runs_configure_and_sweeps_generated_headers():
    sh = cv._VALIDATE_SH
    assert "compile" in sh, "must invoke the project compile/build.sh once"
    assert "_build.h" in sh or "_config.h" in sh, \
        "must -I the dirs holding configure-generated headers"
    assert "|| true" in sh
