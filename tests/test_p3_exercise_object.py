"""Phase-3 per-driver DEPTH: LOGICFUZZ_EXERCISE_OBJECT forward 'exercise the
object' extension. Backward _build_prefix stops at object construction
(cmsCreateTransform); this appends a fuzz-data consumer (cmsDoTransform) so the
built object is actually RUN, not just built+freed. Gated default-off."""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis import sequence_constructor as sc
from liberator_adapter.analysis.api_semantic_model import ArgRole


class _Arg:
    def __init__(self, role):
        self.role = role


class _Sem:
    def __init__(self, name, requires=(), args=()):
        self.name = name
        self.requires = requires
        self.args = args


class _Idx:
    def __init__(self, cbh):
        self.consumers_by_handle = cbh


def test_append_exercisers_runs_built_object():
    do_t = _Sem("cmsDoTransform", requires=("cmshtransform",),
                args=(_Arg(ArgRole.INPUT_BUFFER),))
    idx = _Idx({"cmshtransform": [do_t]})
    out = sc._append_exercisers(
        ["cmsCreate_sRGBProfile", "cmsCreateTransform"], {"cmshtransform"}, idx)
    assert out[-1] == "cmsDoTransform", out


def test_exerciser_not_duplicated():
    do_t = _Sem("cmsDoTransform", requires=("cmshtransform",),
                args=(_Arg(ArgRole.INPUT_BUFFER),))
    idx = _Idx({"cmshtransform": [do_t]})
    out = sc._append_exercisers(
        ["cmsCreateTransform", "cmsDoTransform"], {"cmshtransform"}, idx)
    assert out.count("cmsDoTransform") == 1


def test_exerciser_skips_unsatisfiable_handle():
    # consumer requires a SECOND handle not produced in-chain → skip (NULL-hole).
    needs_two = _Sem("cmsNeedsTwo",
                     requires=("cmshtransform", "cmshprofile2"),
                     args=(_Arg(ArgRole.INPUT_BUFFER),))
    idx = _Idx({"cmshtransform": [needs_two]})
    out = sc._append_exercisers(["cmsCreateTransform"], {"cmshtransform"}, idx)
    assert "cmsNeedsTwo" not in out


def test_exerciser_prefers_fuzz_data_consumer():
    getter = _Sem("cmsGetTransformInputFormat",
                  requires=("cmshtransform",), args=())
    runner = _Sem("cmsDoTransform", requires=("cmshtransform",),
                  args=(_Arg(ArgRole.INPUT_BUFFER),))
    # getter listed first; the fuzz-data runner must still win.
    idx = _Idx({"cmshtransform": [getter, runner]})
    out = sc._append_exercisers(["cmsCreateTransform"], {"cmshtransform"}, idx)
    assert out[-1] == "cmsDoTransform"


def test_exerciser_no_consumers_is_noop():
    idx = _Idx({})
    seq = ["cmsCreate_sRGBProfile"]
    assert sc._append_exercisers(seq, {"cmshprofile"}, idx) == seq


def test_gate_default_off():
    os.environ.pop("LOGICFUZZ_EXERCISE_OBJECT", None)
    assert sc._exercise_object() is False
    os.environ["LOGICFUZZ_EXERCISE_OBJECT"] = "1"
    try:
        assert sc._exercise_object() is True
    finally:
        os.environ.pop("LOGICFUZZ_EXERCISE_OBJECT", None)
