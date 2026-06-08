"""Hard NULL/opaque guards (always on): the advisory NULL/opaque hole notes are
escalated to MANDATORY driver-quality / low-FP guidance. (The
LOGICFUZZ_HARD_NULLGUARD / LOGICFUZZ_DENSE_CONSTRUCT gates were removed — the
guard is unconditional now.)"""
from liberator_adapter.analysis.hole_semantics import (
    _ret_contract_note, _handle_provenance,
)


class _Sem:
    produces = frozenset()
    requires = frozenset({"H*"})


def test_hard_ret_contract_is_mandatory():
    rc = {"f": {"may_return_null": True}}
    note = _ret_contract_note("f", rc)
    assert note.startswith("MUST-GUARD") and "if (!x) return 0;" in note
    rc2 = {"f": {"error_sentinel": "-1 on error"}}
    assert _ret_contract_note("f", rc2).startswith("MUST-CHECK")


def test_hard_provenance_is_factory_chain():
    note = _handle_provenance(_Sem(), "g", set(), {"H*": ["mk"]})[0]
    assert "BUILD IT" in note and "mk(" in note
    assert "Do NOT pass NULL" in note


def test_orphan_handle_unchanged_in_hard_mode():
    # No producer -> still the construct/NULL note (hard mode can't fabricate one).
    note = _handle_provenance(_Sem(), "g", set(), {})[0]
    assert "NO project API produces it" in note
