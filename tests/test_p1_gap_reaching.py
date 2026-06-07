"""build_gap_reaching_seqs: emit a best-effort carrier for each gap API not yet
covered, so the merged union can reach the long tail (uncovered-first)."""
from liberator_adapter.analysis.api_semantic_model import reconcile
from liberator_adapter.analysis.sequence_constructor import build_gap_reaching_seqs


def _api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _arg(type_str):
    return {"type": type_str, "is_const": [False], "name": ""}


def test_emits_one_carrier_per_missing_gap_api():
    apis = [_api("thing_create", [], ret="Thing *"),
            _api("thing_use", [_arg("Thing *")], ret="int"),
            _api("lonely_parse", [_arg("char *")], ret="int")]
    model = reconcile(apis)
    seqs = build_gap_reaching_seqs(
        model, gap_apis={"thing_use", "lonely_parse"}, already_covered=set())
    covered = {a for s in seqs for a in s}
    assert "thing_use" in covered and "lonely_parse" in covered


def test_skips_already_covered():
    apis = [_api("a", [_arg("char *")], ret="int"),
            _api("b", [_arg("char *")], ret="int")]
    model = reconcile(apis)
    seqs = build_gap_reaching_seqs(
        model, gap_apis={"a", "b"}, already_covered={"a", "b"})
    assert seqs == []


def test_cap_bounds_output():
    apis = [_api(f"f{i}", [_arg("char *")], ret="int") for i in range(10)]
    model = reconcile(apis)
    seqs = build_gap_reaching_seqs(
        model, gap_apis={f"f{i}" for i in range(10)}, already_covered=set(), cap=3)
    assert len(seqs) == 3
