"""Phase-3 tests: _root_kind classifier + LOGICFUZZ_OBJCONSTRUCT_FIRST gate.

Tests mirror tests/test_p2_subsystem_recovery.py fixture style:
build APISemantics directly, import only the public/private helpers.
"""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    APISemantics, APIRole, ArgRole, ArgSemantics, reconcile,
)
from liberator_adapter.analysis.sequence_constructor import (  # noqa: E402
    _root_kind, construct_sequences,
)


def _arg(i, role, t="void"):
    return ArgSemantics(index=i, role=role, type_str=t)


def _api(name, role, produces=(), requires=(), args=()):
    return APISemantics(
        name=name, role=role, role_confidence=0.9, args=tuple(args),
        produces=frozenset(produces), requires=frozenset(requires),
        destroys=frozenset(),
    )


# ---------------------------------------------------------------------------
# _root_kind tests
# ---------------------------------------------------------------------------

def test_root_kind_parser_entry():
    """A CREATOR with an INPUT_BUFFER arg is a parser_entry."""
    a = _api(
        "cmsOpenProfileFromMem",
        APIRole.CREATOR,
        produces={"hprofile*"},
        args=(
            _arg(0, ArgRole.INPUT_BUFFER, "const void*"),
            _arg(1, ArgRole.LENGTH, "size_t"),
        ),
    )
    assert _root_kind(a) == "parser_entry"


def test_root_kind_data_buildable():
    """A CREATOR with no INPUT_BUFFER arg (synthetic builder) is data_buildable."""
    a = _api("cmsCreate_sRGBProfile", APIRole.CREATOR, produces={"hprofile*"}, args=())
    assert _root_kind(a) == "data_buildable"


def test_root_kind_caller_alloc():
    """A CREATOR whose only arg is an OUTPUT pointer (caller-alloc) is caller_alloc."""
    a = _api(
        "deflateInit",
        APIRole.CREATOR,
        produces={"z_stream*"},
        args=(_arg(0, ArgRole.OUTPUT, "z_stream*"),),
    )
    assert _root_kind(a) == "caller_alloc"


def test_root_kind_consumer_with_buffer_is_parser_entry():
    """A CONSUMER with an INPUT_BUFFER arg also counts as parser_entry."""
    a = _api(
        "parseBuffer",
        APIRole.CONSUMER,
        args=(_arg(0, ArgRole.INPUT_BUFFER, "const char*"),),
    )
    assert _root_kind(a) == "parser_entry"


def test_root_kind_mutator_no_buffer():
    """A MUTATOR without INPUT_BUFFER is 'other'."""
    a = _api(
        "cmsSetHeaderFlags",
        APIRole.MUTATOR,
        requires={"hprofile*"},
        args=(_arg(0, ArgRole.HANDLE_IN, "hprofile*"), _arg(1, ArgRole.CONFIG, "int")),
    )
    assert _root_kind(a) == "other"


def test_root_kind_destroyer_is_other():
    """A DESTROYER is always 'other'."""
    a = _api("cmsFreeProfile", APIRole.DESTROYER, args=())
    assert _root_kind(a) == "other"


def test_root_kind_data_buildable_with_config_arg():
    """A CREATOR with only CONFIG args (no INPUT_BUFFER, no OUTPUT) is data_buildable."""
    a = _api(
        "cmsCreateGrayProfile",
        APIRole.CREATOR,
        produces={"hprofile*"},
        args=(_arg(0, ArgRole.CONFIG, "double"),),
    )
    assert _root_kind(a) == "data_buildable"


# ---------------------------------------------------------------------------
# Gate test: LOGICFUZZ_OBJCONSTRUCT_FIRST env flag is importable + is a bool
# ---------------------------------------------------------------------------

def test_gate_is_bool():
    """The _OBJCONSTRUCT_FIRST module-level gate must be a boolean."""
    from liberator_adapter.analysis.sequence_constructor import _OBJCONSTRUCT_FIRST
    assert isinstance(_OBJCONSTRUCT_FIRST, bool)


def test_gate_default_off():
    """Default (env unset) must be False so baseline is unchanged."""
    import importlib
    import liberator_adapter.analysis.sequence_constructor as sc_mod
    # Only check default when the env var is absent.
    if "LOGICFUZZ_OBJCONSTRUCT_FIRST" not in os.environ:
        assert sc_mod._OBJCONSTRUCT_FIRST is False


# ---------------------------------------------------------------------------
# Helpers for integration tests (construct_sequences)
# ---------------------------------------------------------------------------

def _raw_api(name, args=None, ret="void"):
    return {"function_name": name, "arguments": args or [],
            "return_type": ret, "is_vararg": False, "namespace": []}


def _raw_arg(type_str, const=False, name=""):
    return {"type": type_str, "is_const": [bool(const)], "name": name}


def _lcms_subsystem():
    """Minimal lcms-like subsystem with BOTH a parser-entry creator
    (cmsOpenProfileFromMem) AND a data-buildable creator (cmsCreate_sRGBProfile)
    producing the same handle, plus a consumer and destroyer.
    """
    return [
        # parser-entry creator: needs fuzzer bytes → hProfile*
        _raw_api(
            "cmsOpenProfileFromMem",
            [_raw_arg("const void *", const=True, name="MemPtr"),
             _raw_arg("unsigned int", name="dwSize")],
            ret="cmsHPROFILE",
        ),
        # data-buildable creator: no INPUT_BUFFER → hProfile*
        _raw_api("cmsCreate_sRGBProfile", [], ret="cmsHPROFILE"),
        # consumer of the profile handle
        _raw_api(
            "cmsReadTag",
            [_raw_arg("cmsHPROFILE", name="hProfile"),
             _raw_arg("unsigned int", name="sig")],
            ret="void *",
        ),
        # destroyer
        _raw_api("cmsCloseProfile", [_raw_arg("cmsHPROFILE", name="hProfile")]),
    ]


def _first_creator(sequences):
    """Return the first creator API seen across the ordered sequence list."""
    creator_names = {"cmsOpenProfileFromMem", "cmsCreate_sRGBProfile"}
    for seq in sequences:
        for api in seq:
            if api in creator_names:
                return api
    return None


# ---------------------------------------------------------------------------
# Integration: construct_sequences ordering under LOGICFUZZ_OBJCONSTRUCT_FIRST
# ---------------------------------------------------------------------------

def test_gate_off_parser_entry_sequences_first(monkeypatch):
    """Gate OFF (default): a parser-rooted sequence appears before any
    data-buildable-rooted sequence (baseline regression check)."""
    monkeypatch.delenv("LOGICFUZZ_OBJCONSTRUCT_FIRST", raising=False)
    import liberator_adapter.analysis.sequence_constructor as sc
    sc._OBJCONSTRUCT_FIRST = False   # force gate off in-process

    apis = _lcms_subsystem()
    model = reconcile(apis)
    res = construct_sequences(model, project_apis=apis)

    # Gate OFF: parser-entry creator should appear first.
    first = _first_creator(res.sequences)
    assert first == "cmsOpenProfileFromMem", (
        f"Gate OFF: expected parser-entry first, got {first!r}. "
        f"Sequences: {res.sequences[:5]}"
    )
    # Parser-rooted sequence must still be present.
    assert any("cmsOpenProfileFromMem" in s for s in res.sequences)


def test_gate_on_data_buildable_sequences_first(monkeypatch):
    """Gate ON: a data-buildable-rooted sequence appears BEFORE any
    parser-rooted sequence. Both kinds must still be present."""
    monkeypatch.setenv("LOGICFUZZ_OBJCONSTRUCT_FIRST", "1")
    import liberator_adapter.analysis.sequence_constructor as sc
    sc._OBJCONSTRUCT_FIRST = True   # force gate on in-process

    apis = _lcms_subsystem()
    model = reconcile(apis)
    res = construct_sequences(model, project_apis=apis)

    # Gate ON: data-buildable creator should appear first.
    first = _first_creator(res.sequences)
    assert first == "cmsCreate_sRGBProfile", (
        f"Gate ON: expected data-buildable first, got {first!r}. "
        f"Sequences: {res.sequences[:5]}"
    )
    # Parser-rooted sequence must STILL be present (breadth is not lost).
    assert any("cmsOpenProfileFromMem" in s for s in res.sequences), (
        "Gate ON: parser-rooted sequence missing — breadth was lost"
    )
    # Data-buildable sequence must be present.
    assert any("cmsCreate_sRGBProfile" in s for s in res.sequences)


def test_gate_on_parser_only_subsystem_still_yields_sequences(monkeypatch):
    """Gate ON with a parser-ONLY subsystem (no data-buildable creator):
    the parser-entry creator must still appear in some sequence."""
    monkeypatch.setenv("LOGICFUZZ_OBJCONSTRUCT_FIRST", "1")
    import liberator_adapter.analysis.sequence_constructor as sc
    sc._OBJCONSTRUCT_FIRST = True

    # Only a buffer creator (no synthetic builder).
    apis = [
        _raw_api(
            "parserCreate",
            [_raw_arg("const uint8_t *", const=True, name="buf"),
             _raw_arg("size_t", name="len")],
            ret="Parser *",
        ),
        _raw_api("parserProcess",
                 [_raw_arg("Parser *", name="p")], ret="int"),
        _raw_api("parserFree", [_raw_arg("Parser *", name="p")]),
    ]
    model = reconcile(apis)
    res = construct_sequences(model, project_apis=apis)

    assert len(res.sequences) > 0, "Gate ON: no sequences produced for parser-only subsystem"
    assert any("parserCreate" in s for s in res.sequences), (
        "Gate ON: parser-only creator missing from all sequences"
    )


def test_gate_on_target_pool_prepends_data_buildable(monkeypatch):
    """Gate ON: data-buildable creators appear in the target_pool before
    parser-entry creators, so bottom-up construction visits them first.
    Verified by checking sequence ordering."""
    monkeypatch.setenv("LOGICFUZZ_OBJCONSTRUCT_FIRST", "1")
    import liberator_adapter.analysis.sequence_constructor as sc
    sc._OBJCONSTRUCT_FIRST = True

    apis = _lcms_subsystem()
    model = reconcile(apis)
    res = construct_sequences(model, project_apis=apis)

    # Collect all creator-first positions.
    db_positions = []
    pe_positions = []
    for i, seq in enumerate(res.sequences):
        if seq and seq[0] == "cmsCreate_sRGBProfile":
            db_positions.append(i)
        elif seq and seq[0] == "cmsOpenProfileFromMem":
            pe_positions.append(i)

    # If there are both kinds, data-buildable should appear earlier.
    if db_positions and pe_positions:
        assert min(db_positions) < min(pe_positions), (
            f"Gate ON: data-buildable first occurrence at position {min(db_positions)} "
            f"is AFTER parser-entry at {min(pe_positions)}"
        )
