# tests/test_input_source.py
from liberator_adapter.analysis.input_source import classify_input_source, materialize
from liberator_adapter.analysis.api_semantic_model import APIRole

def test_classify_file_star_high():
    assert classify_input_source("FILE *", APIRole.CREATOR) == ("FILE_STAR", "HIGH")

def test_classify_char_path_low():
    assert classify_input_source("const char *", APIRole.CREATOR) == ("PATH", "LOW")

def test_classify_buffer_and_non_creator_none():
    assert classify_input_source("const uint8_t *", APIRole.CREATOR) is None
    assert classify_input_source("const char *", APIRole.CONSUMER) is None

def test_materialize_file_star():
    m = materialize("FILE_STAR", "src0")
    assert any("fmemopen" in s for s in m.stmts)
    assert m.bind_expr == "src0_f"
    assert any("fclose" in c for c in m.cleanup)
    assert "<stdio.h>" in m.includes

def test_materialize_path():
    m = materialize("PATH", "src0")
    assert any("mkstemp" in s for s in m.stmts) and any("write(" in s for s in m.stmts)
    assert m.bind_expr == "src0_path"
    assert any("unlink" in c for c in m.cleanup)
    assert "<unistd.h>" in m.includes
