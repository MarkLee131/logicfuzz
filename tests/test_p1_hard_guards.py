"""LOGICFUZZ_HARD_NULLGUARD: escalate advisory NULL/opaque notes to MANDATORY
guidance (driver-quality / low-FP). Default off = byte-identical advisory text."""
import os
import pytest
from liberator_adapter.analysis.hole_semantics import (
    _ret_contract_note, _handle_provenance, _hard_nullguard,
)


@pytest.fixture(autouse=True)
def _clear_env():
    os.environ.pop("LOGICFUZZ_HARD_NULLGUARD", None)
    yield
    os.environ.pop("LOGICFUZZ_HARD_NULLGUARD", None)


class _Sem:
    produces = frozenset()
    requires = frozenset({"H*"})


def test_default_off_keeps_advisory():
    assert not _hard_nullguard()
    rc = {"f": {"may_return_null": True}}
    assert _ret_contract_note("f", rc).startswith("⚠")
    note = _handle_provenance(_Sem(), "g", set(), {"H*": ["mk"]})[0]
    assert "produced by mk" in note and "BUILD IT" not in note


def test_hard_ret_contract_is_mandatory():
    os.environ["LOGICFUZZ_HARD_NULLGUARD"] = "1"
    rc = {"f": {"may_return_null": True}}
    note = _ret_contract_note("f", rc)
    assert note.startswith("MUST-GUARD") and "if (!x) return 0;" in note
    rc2 = {"f": {"error_sentinel": "-1 on error"}}
    assert _ret_contract_note("f", rc2).startswith("MUST-CHECK")


def test_hard_provenance_is_factory_chain():
    os.environ["LOGICFUZZ_HARD_NULLGUARD"] = "1"
    note = _handle_provenance(_Sem(), "g", set(), {"H*": ["mk"]})[0]
    assert "BUILD IT" in note and "mk(" in note
    assert "Do NOT pass NULL" in note


def test_orphan_handle_unchanged_in_hard_mode():
    # No producer -> still the construct/NULL note (hard mode can't fabricate one).
    os.environ["LOGICFUZZ_HARD_NULLGUARD"] = "1"
    note = _handle_provenance(_Sem(), "g", set(), {})[0]
    assert "NO project API produces it" in note
