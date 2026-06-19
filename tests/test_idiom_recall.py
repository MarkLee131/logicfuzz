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
    # A genuine filesystem path is a lone char* with no following size, classed
    # CONFIG/UNKNOWN — NOT INPUT_BUFFER.
    sem = _api(APIRole.CREATOR, [
        _arg(0, ArgRole.CONFIG, "const char *"),         # path (lone char*, no size)
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


def test_parser_input_buffer_not_routed_to_file():
    # Regression: a memory-parser CREATOR — e.g. cmsOpenProfileFromMem(buf, len)
    # — must NOT emit FILE_FROM_FUZZ for its INPUT_BUFFER arg (arg0).
    # The primary fuzz buffer (INPUT_BUFFER char* + LENGTH size_t) is fed directly
    # to the parser, never written to a temp file.
    sem = _api(APIRole.CREATOR, [
        _arg(0, ArgRole.INPUT_BUFFER, "const char *"),   # raw fuzz buffer
        _arg(1, ArgRole.LENGTH, "size_t"),               # buffer length
    ])
    assert file_opener_intents(sem) == {}


# ---------------------------------------------------------------------------
# Task 2: value_intents_for_sequence wiring (gated by LOGICFUZZ_DISABLE_RECALL)
# ---------------------------------------------------------------------------
import os
from liberator_adapter.analysis.hole_semantics import value_intents_for_sequence
from liberator_adapter.analysis.api_semantic_model import APISemanticModel


def _opener_model():
    # A genuine filesystem opener: path is a lone char* (CONFIG), not INPUT_BUFFER.
    from liberator_adapter.analysis.api_semantic_model import APISemantics
    sem_named = APISemantics(
        name="openf",
        role=APIRole.CREATOR,
        role_confidence=1.0,
        args=tuple([
            _arg(0, ArgRole.CONFIG, "const char *"),   # path (lone char*, no size)
            _arg(1, ArgRole.CONFIG, "const char *"),   # mode
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


# ---------------------------------------------------------------------------
# Task 3: count_file_idiom_skeletons counter
# ---------------------------------------------------------------------------
from liberator_adapter.analysis.hole_semantics import count_file_idiom_skeletons


def test_count_file_idiom_skeletons():
    skels = [
        {"value_intents": [{"args": [{"index": 0, "intent": "FILE_FROM_FUZZ: ..."}]}]},
        {"value_intents": [{"args": [{"index": 0, "intent": "FUZZ_DERIVE: enum"}]}]},
        {"value_intents": []},
    ]
    assert count_file_idiom_skeletons(skels) == 1
