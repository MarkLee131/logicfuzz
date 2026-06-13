"""header_facts — deterministic per-(api, arg_idx) literal fills for INIT scalar args.

Tests:
  1. Module API: set_fact_map / literal_for basic contract.
  2. Render integration: a CONFIG scalar arg with a registered fact renders
     the literal in the skeleton output (not a hole placeholder or ``0``).
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis import header_facts  # noqa: E402


# ---------------------------------------------------------------------------
# Test 1: module API contract
# ---------------------------------------------------------------------------

def test_literal_for_set_and_read():
    header_facts.set_fact_map({"deflateInit_": {2: "ZLIB_VERSION", 3: "(int)sizeof(z_stream)"}})
    assert header_facts.literal_for("deflateInit_", 2) == "ZLIB_VERSION"
    assert header_facts.literal_for("deflateInit_", 3) == "(int)sizeof(z_stream)"
    assert header_facts.literal_for("deflateInit_", 0) is None
    assert header_facts.literal_for("unknown", 0) is None


def test_literal_for_empty_map_returns_none():
    header_facts.set_fact_map(None)
    assert header_facts.literal_for("deflateInit_", 2) is None


def test_literal_for_overwrite():
    header_facts.set_fact_map({"foo": {0: "FOO_A"}})
    assert header_facts.literal_for("foo", 0) == "FOO_A"
    header_facts.set_fact_map({"foo": {0: "FOO_B"}})
    assert header_facts.literal_for("foo", 0) == "FOO_B"


# ---------------------------------------------------------------------------
# Test 2: render integration — header fact appears in rendered skeleton code
# ---------------------------------------------------------------------------

def test_header_fact_literal_in_rendered_skeleton():
    """When a header fact is registered for (api, arg_idx) the rendered
    skeleton must contain that literal as the init_value for that arg."""
    import os

    # Clear any scoped-guards env so render is deterministic
    os.environ.pop("LOGICFUZZ_SCOPED_GUARDS", None)

    from liberator_adapter.analysis.api_semantic_model import reconcile
    from liberator_adapter.common.api import Api, Arg
    from liberator_adapter.driver.synthesis.skeleton_generator import (
        SkeletonGenerator, SkeletonRenderer,
    )

    # A tiny API that has one CONFIG scalar arg (int level) and a void* creator.
    # reconcile() will see arg1 of deflateInit_ (level, int) as CONFIG SCALAR.
    apis_dict = [
        {
            "function_name": "zlib_create",
            "arguments": [],
            "return_type": "void *",
            "is_vararg": False,
            "namespace": [],
        },
        {
            "function_name": "deflateInit_",
            "arguments": [
                {"type": "void *",    "is_const": [False], "name": "strm"},   # HANDLE_IN
                {"type": "int",       "is_const": [False], "name": "level"},  # CONFIG SCALAR
                {"type": "const char *", "is_const": [True], "name": "version"},  # ignored
                {"type": "int",       "is_const": [False], "name": "stream_size"},  # CONFIG SCALAR
            ],
            "return_type": "int",
            "is_vararg": False,
            "namespace": [],
        },
    ]

    # Register facts for the two CONFIG scalar args (idx 1 and idx 3)
    header_facts.set_fact_map({
        "deflateInit_": {
            1: "Z_DEFAULT_COMPRESSION",
            3: "(int)sizeof(z_stream)",
        }
    })

    model = reconcile(apis_dict)

    def _arg(n, t, c=False):
        return Arg(name=n, flag="", size=0, type=t,
                   is_const=[c], is_type_incomplete=False)

    def _api(n, rt, args):
        return Api(function_name=n, is_vararg=False,
                   return_info=_arg("r", rt), arguments_info=args, namespace=[])

    seq = [
        _api("zlib_create", "void *", []),
        _api("deflateInit_", "int", [
            _arg("strm",        "void *"),
            _arg("level",       "int"),
            _arg("version",     "const char *", True),
            _arg("stream_size", "int"),
        ]),
    ]

    sk = SkeletonGenerator().generate(
        api_sequence=seq, driver_name="t", is_cpp=False, dep_model=model)
    code = SkeletonRenderer().render(sk)

    # At least one of the registered literals must appear in the rendered code
    assert "Z_DEFAULT_COMPRESSION" in code or "(int)sizeof(z_stream)" in code, (
        "Expected a header-fact literal in rendered skeleton, got:\n" + code
    )
