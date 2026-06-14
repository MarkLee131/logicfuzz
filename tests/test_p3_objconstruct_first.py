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
    APISemantics, APIRole, ArgRole, ArgSemantics,
)
from liberator_adapter.analysis.sequence_constructor import _root_kind  # noqa: E402


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
