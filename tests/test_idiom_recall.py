"""Tests for idiom-aware recall helpers (Task 1: FILE_FROM_FUZZ intent)."""
from liberator_adapter.analysis.api_semantic_model import (
    APISemantics, ArgSemantics, APIRole, ArgRole)
from liberator_adapter.analysis.hole_semantics import file_opener_intents


def _api(role, args):
    return APISemantics(name="x", role=role, role_confidence=1.0, args=tuple(args))

def _arg(i, role, t):
    return ArgSemantics(index=i, role=role, type_str=t)


def test_creator_charptr_path_gets_file_from_fuzz():
    # gzopen(const char* path, const char* mode) — CREATOR returning a handle
    sem = _api(APIRole.CREATOR, [
        _arg(0, ArgRole.INPUT_BUFFER, "const char *"),   # path
        _arg(1, ArgRole.CONFIG, "const char *"),         # mode
    ])
    intents = file_opener_intents(sem)
    assert "FILE_FROM_FUZZ" in intents[0]                # path arg
    assert "tmp" in intents[0].lower() and "NULL" in intents[0]
    assert "FUZZ_DERIVE" in intents[1] and '"rb"' in intents[1]  # mode value-domain


def test_non_creator_is_empty():
    sem = _api(APIRole.CONSUMER, [_arg(0, ArgRole.INPUT_BUFFER, "const char *")])
    assert file_opener_intents(sem) == {}


def test_creator_without_charptr_is_empty():
    # deflateInit_ style — no char* path arg
    sem = _api(APIRole.CREATOR, [_arg(0, ArgRole.HANDLE_IN, "z_stream *")])
    assert file_opener_intents(sem) == {}


def test_length_and_output_charptr_skipped():
    sem = _api(APIRole.CREATOR, [
        _arg(0, ArgRole.OUTPUT, "char *"),     # out buffer, not a path
        _arg(1, ArgRole.LENGTH, "char *"),     # (degenerate type) length
    ])
    assert file_opener_intents(sem) == {}


# ---------------------------------------------------------------------------
# Task 2: value_intents_for_sequence wiring (gated by LOGICFUZZ_DISABLE_RECALL)
# ---------------------------------------------------------------------------
import os
from liberator_adapter.analysis.hole_semantics import value_intents_for_sequence
from liberator_adapter.analysis.api_semantic_model import APISemanticModel


def _opener_model():
    sem = _api(APIRole.CREATOR, [
        _arg(0, ArgRole.INPUT_BUFFER, "const char *"),
        _arg(1, ArgRole.CONFIG, "const char *"),
    ])
    # APISemantics is frozen but its name field defaults to "x" via _api helper;
    # rebuild with name="openf" so model.get("openf") resolves it.
    from liberator_adapter.analysis.api_semantic_model import APISemantics
    sem_named = APISemantics(
        name="openf",
        role=APIRole.CREATOR,
        role_confidence=1.0,
        args=tuple([
            _arg(0, ArgRole.INPUT_BUFFER, "const char *"),
            _arg(1, ArgRole.CONFIG, "const char *"),
        ]),
    )
    return APISemanticModel(project="", apis={"openf": sem_named})


def test_file_intent_appears_in_records(monkeypatch):
    monkeypatch.delenv("LOGICFUZZ_DISABLE_RECALL", raising=False)
    recs = value_intents_for_sequence(_opener_model(), ["openf"])
    arg0 = [a for r in recs for a in r["args"] if a["index"] == 0][0]
    assert "FILE_FROM_FUZZ" in arg0["intent"]


def test_gate_disables_file_intent(monkeypatch):
    monkeypatch.setenv("LOGICFUZZ_DISABLE_RECALL", "1")
    recs = value_intents_for_sequence(_opener_model(), ["openf"])
    arg0s = [a for r in recs for a in r["args"] if a["index"] == 0]
    assert all("FILE_FROM_FUZZ" not in a["intent"] for a in arg0s)
