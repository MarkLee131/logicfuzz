"""T1: lift SVF set_by (param→param init dependency) into hole value-intents."""
from liberator_adapter.analysis.hole_semantics import (
    value_intents_for_sequence, render_value_intents,
)
from liberator_adapter.analysis.api_semantic_model import ArgRole


class _Arg:
    def __init__(self, index, role=ArgRole.CONFIG, type_str="int *"):
        self.index = index
        self.role = role
        self.type_str = type_str
        self.pairs_with = None


class _Sem:
    def __init__(self, args, role="MUTATOR"):
        self.args = args
        self.produces = frozenset()
        self.requires = frozenset()
        class _R:
            value = role
        self.role = _R()


class _Model:
    def __init__(self, apis):
        self.apis = apis
    def get(self, n):
        return self.apis.get(n)


def _model():
    return _Model({"append": _Sem([_Arg(0, ArgRole.HANDLE_IN, "List *"),
                                   _Arg(2), _Arg(3)])})


def test_set_by_attaches_populated_from():
    svf = {"append": {0: {"set_by": [2, 3]}}}
    recs = value_intents_for_sequence(_model(), ["append"], None, svf)
    arg0 = next(a for a in recs[0]["args"] if a["index"] == 0)
    assert arg0["populated_from"] == [2, 3]


def test_no_svf_index_is_noop():
    recs = value_intents_for_sequence(_model(), ["append"], None, None)
    arg0 = next((a for a in recs[0]["args"] if a["index"] == 0), {})
    assert "populated_from" not in arg0


def test_render_shows_populated_from():
    svf = {"append": {0: {"set_by": [2, 3]}}}
    txt = render_value_intents(value_intents_for_sequence(_model(), ["append"], None, svf))
    assert "POPULATED_FROM arg2, arg3" in txt


def test_arg_with_only_set_by_still_recorded():
    # An arg with no role-intent but a set_by must still appear.
    m = _Model({"f": _Sem([_Arg(1, ArgRole.OUTPUT, "void *")])})
    svf = {"f": {1: {"set_by": [0]}}}
    recs = value_intents_for_sequence(m, ["f"], None, svf)
    arg1 = next(a for a in recs[0]["args"] if a["index"] == 1)
    assert arg1["populated_from"] == [0]
