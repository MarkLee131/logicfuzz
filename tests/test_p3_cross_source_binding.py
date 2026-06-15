"""Binding-layer post-pass for the cross-source transform lever.

After upstream RunningContext wires args, two same-type handle args of a CREATOR
(e.g. cmsCreateTransform's 2x cmsHPROFILE) bind to the SAME producer (upstream
defers context ``update`` until all args resolve, so both pick the first live
profile). ``_distribute_cross_source`` re-points the 2nd same-type arg to a
DIFFERENT earlier producer of that type (the construction-injected synthetic
profile), turning a same-profile (~identity) transform into a CROSS-profile one
that executes the conversion code (+134% edges, handcrafted A/B).

It is CREATOR-scoped (``is_producer``) + name-deny so it can't mis-fire on
copy/state APIs (``deflateCopy`` returns int → not a producer) or
parent-child/detach APIs (name-deny). Pure function, no env read — the caller
gates on ``LOGICFUZZ_CROSS_SOURCE_BIND`` so gate-off is byte-identical.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.driver.factory.constraint_based.CBFactory import (  # noqa: E402
    _distribute_cross_source,
)


def _rec(name, is_producer, ret_token, arg_tokens):
    return {"name": name, "is_producer": is_producer,
            "ret_token": ret_token, "arg_tokens": arg_tokens}


def test_repoints_second_same_type_arg_to_distinct_producer():
    ordered = [
        _rec("openP", True, "i8*", {0: "i8*", 1: "i32"}),
        _rec("makeP", True, "i8*", {}),
        _rec("xform", True, "i8*", {0: "i8*", 2: "i8*"}),
    ]
    bindings = {("xform", 0): "ret_openP", ("xform", 2): "ret_openP"}
    out = _distribute_cross_source(bindings, ordered)
    assert out[("xform", 0)] == "ret_openP", out
    assert out[("xform", 2)] == "ret_makeP", out


def test_prefers_nearest_earlier_producer_as_alternate():
    # two alternates available; the one registered LAST (nearest, = the
    # construction-injected synthetic producer) is preferred for arg2.
    ordered = [
        _rec("makeFar", True, "i8*", {}),
        _rec("openP", True, "i8*", {0: "i8*"}),
        _rec("makeNear", True, "i8*", {}),
        _rec("xform", True, "i8*", {0: "i8*", 2: "i8*"}),
    ]
    bindings = {("xform", 0): "ret_openP", ("xform", 2): "ret_openP"}
    out = _distribute_cross_source(bindings, ordered)
    assert out[("xform", 0)] == "ret_openP", out
    assert out[("xform", 2)] == "ret_makeNear", out


def test_noop_when_only_one_producer_of_type():
    ordered = [
        _rec("openP", True, "i8*", {0: "i8*"}),
        _rec("xform", True, "i8*", {0: "i8*", 2: "i8*"}),
    ]
    bindings = {("xform", 0): "ret_openP", ("xform", 2): "ret_openP"}
    out = _distribute_cross_source(bindings, ordered)
    assert out == bindings, out


def test_noop_when_already_distinct():
    ordered = [
        _rec("openP", True, "i8*", {}),
        _rec("makeP", True, "i8*", {}),
        _rec("xform", True, "i8*", {0: "i8*", 2: "i8*"}),
    ]
    bindings = {("xform", 0): "ret_openP", ("xform", 2): "ret_makeP"}
    out = _distribute_cross_source(bindings, ordered)
    assert out == bindings, out


def test_noop_on_deny_named_copy_api():
    # a copy/clone-named producer must NOT be cross-source bound even if it
    # happens to return a handle and take 2 same-type args.
    ordered = [
        _rec("openP", True, "i8*", {}),
        _rec("makeP", True, "i8*", {}),
        _rec("fooCopy", True, "i8*", {0: "i8*", 1: "i8*"}),
    ]
    bindings = {("fooCopy", 0): "ret_openP", ("fooCopy", 1): "ret_openP"}
    out = _distribute_cross_source(bindings, ordered)
    assert out == bindings, out


def test_noop_on_non_producer_consumer():
    # CREATOR-scope: a consumer (ret not a handle → is_producer False) with two
    # same-type args is left untouched (its 2 handles may need a relationship).
    ordered = [
        _rec("openP", True, "i8*", {}),
        _rec("makeP", True, "i8*", {}),
        _rec("useBoth", False, None, {0: "i8*", 1: "i8*"}),
    ]
    bindings = {("useBoth", 0): "ret_openP", ("useBoth", 1): "ret_openP"}
    out = _distribute_cross_source(bindings, ordered)
    assert out == bindings, out


# ---- integration: _signature_handle_bindings (the model_unchecked path that
# actually wires opaque void* transform handles; RunningContext rejects them) ---
import types  # noqa: E402

from liberator_adapter.driver.factory.constraint_based.CBFactory import (  # noqa: E402
    CBFactory,
)


def _api(name, arg_types, ret_type):
    return types.SimpleNamespace(
        function_name=name,
        arguments_info=[types.SimpleNamespace(type=t) for t in arg_types],
        return_info=types.SimpleNamespace(type=ret_type),
    )


def _xform_seq():
    return [
        _api("openP", ["void *", "unsigned int"], "void *"),
        _api("makeP", [], "void *"),
        _api("xform", ["void *", "unsigned int", "void *",
                       "unsigned int"], "void *"),
    ]


def test_signature_bindings_legacy_binds_both_args_to_last_producer(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_CROSS_SOURCE_BIND", raising=False)
    sig = CBFactory._signature_handle_bindings.__get__(types.SimpleNamespace())
    out = sig(_xform_seq())
    # legacy: produced[type]=last → both profile args bind to ret_makeP
    assert out[("xform", 0)] == out[("xform", 2)] == "ret_makeP", out


def test_signature_bindings_cross_source_distributes(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_CROSS_SOURCE_BIND", "1")
    sig = CBFactory._signature_handle_bindings.__get__(types.SimpleNamespace())
    out = sig(_xform_seq())
    # gate-on: the two same-type handle args bind to DIFFERENT producers
    assert out[("xform", 0)] != out[("xform", 2)], out
    assert {out[("xform", 0)], out[("xform", 2)]} == {"ret_makeP", "ret_openP"}, out


def test_signature_bindings_cross_source_noop_single_arg(monkeypatch):
    # a CREATOR with only ONE handle arg is unaffected (no same-type pair).
    monkeypatch.setenv("LOGICFUZZ_CROSS_SOURCE_BIND", "1")
    sig = CBFactory._signature_handle_bindings.__get__(types.SimpleNamespace())
    seq = [
        _api("openP", [], "void *"),
        _api("makeP", [], "void *"),
        _api("useOne", ["void *", "unsigned int"], "void *"),
    ]
    out = sig(seq)
    assert out[("useOne", 0)] == "ret_makeP", out  # legacy last-producer
