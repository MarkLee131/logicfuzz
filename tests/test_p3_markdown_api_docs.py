"""Parity fix — ingest prose API docs (doc/api.md) the headers don't carry.

Our knowledge layer only read README + header doxygen, so a library that
documents its public API in ``doc/api.md`` (libucl: 506 lines of per-function
reference) handed a doc-driven baseline (PromeFuzz's ``document_paths``) a
semantic edge we threw away. ``extract_markdown_api_docs`` mines those files
into the SAME ``{brief, params, returns}`` record as the header path, so the
markdown reference feeds the Comprehender + APISemanticModel identically.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.knowledge.project_docs import (  # noqa: E402
    extract_markdown_api_docs,
    _heading_to_api,
    _params_from_signature,
    _record_from_body,
)

_API_MD = """# API documentation

- [ucl_parser_new](#ucl_parser_new)
- [ucl_parser_add_chunk](#ucl_parser_add_chunk)

## Parser functions

### ucl_parser_new

~~~C
struct ucl_parser* ucl_parser_new (int flags);
~~~

Creates a new UCL parser object. The flags argument tunes parser behaviour;
pass 0 for the defaults. Returns the new parser, or NULL on allocation failure.

### ucl_parser_add_chunk

```C
bool ucl_parser_add_chunk (struct ucl_parser *parser, const unsigned char *data, size_t len);
```

Adds a chunk of text to the parser. `data` is the input buffer of size `len`
bytes. Returns true if the chunk was parsed successfully.

### unrelated_helper

Not a public API; must be ignored.
"""


def _write(tmp_path, rel, body):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def test_heading_to_api_forms():
    s = {"ucl_parser_new"}
    assert _heading_to_api("ucl_parser_new", s) == "ucl_parser_new"
    assert _heading_to_api("ucl_parser_new()", s) == "ucl_parser_new"
    assert _heading_to_api("`ucl_parser_new`", s) == "ucl_parser_new"
    assert _heading_to_api("[ucl_parser_new](#x)", s) == "ucl_parser_new"
    assert _heading_to_api("Parser functions", s) is None


def test_params_from_signature():
    ps = _params_from_signature(
        "bool ucl_parser_add_chunk (struct ucl_parser *parser, "
        "const unsigned char *data, size_t len);",
        "ucl_parser_add_chunk")
    assert [p["name"] for p in ps] == ["parser", "data", "len"]
    # role inference rides on the existing _param_role_from_text cues
    assert ps[2]["role"] == "LENGTH"          # "size_t len"


def test_record_brief_and_returns():
    body = [
        "",
        "Creates a new UCL parser object. Returns the parser or NULL.",
        "",
    ]
    rec = _record_from_body(body, "ucl_parser_new")
    assert rec["brief"].startswith("Creates a new UCL parser")
    assert "return" in rec["returns"].lower()


def test_extract_from_doc_dir(tmp_path):
    _write(tmp_path, "doc/api.md", _API_MD)
    api_names = ["ucl_parser_new", "ucl_parser_add_chunk", "ucl_object_lookup"]
    docs = extract_markdown_api_docs(tmp_path, api_names)
    # the two documented APIs are mined; the undocumented one is absent
    assert set(docs) == {"ucl_parser_new", "ucl_parser_add_chunk"}
    assert "unrelated_helper" not in docs            # not in api_set → ignored
    new = docs["ucl_parser_new"]
    assert "UCL parser" in new["brief"]
    assert new["returns"]
    add = docs["ucl_parser_add_chunk"]
    assert [p["name"] for p in add["params"]] == ["parser", "data", "len"]


def test_toc_heading_does_not_shadow_real_section(tmp_path):
    # The bullet TOC names the APIs but carries no body; the real ### sections
    # must win (non-empty record), not the empty TOC occurrence.
    _write(tmp_path, "docs/reference.md", _API_MD)
    docs = extract_markdown_api_docs(tmp_path, ["ucl_parser_new"])
    assert docs["ucl_parser_new"].get("brief")


def test_top_level_api_md(tmp_path):
    _write(tmp_path, "api.md", _API_MD)         # not under doc/, top-level
    docs = extract_markdown_api_docs(tmp_path, ["ucl_parser_new"])
    assert "ucl_parser_new" in docs


def test_empty_when_no_docs(tmp_path):
    (tmp_path / "src").mkdir()
    assert extract_markdown_api_docs(tmp_path, ["foo"]) == {}
    assert extract_markdown_api_docs(tmp_path, []) == {}
    assert extract_markdown_api_docs(None, ["foo"]) == {}


def test_real_libucl_api_md_smoke():
    """If the libucl extraction is on disk, the real doc/api.md mines APIs."""
    import glob
    cand = glob.glob(os.path.join(
        ROOT, "results", "libucl", "src_ossfuzz", "libucl", "doc", "api.md"))
    if not cand:
        return                                  # extraction not present → skip
    src_root = os.path.dirname(os.path.dirname(cand[0]))   # .../libucl
    docs = extract_markdown_api_docs(
        src_root,
        ["ucl_parser_new", "ucl_parser_add_string", "ucl_parser_add_chunk",
         "ucl_object_emit", "ucl_parser_get_object", "ucl_object_validate"])
    # the real api.md documents these; expect a meaningful subset mined
    assert "ucl_parser_new" in docs, list(docs)
    assert docs["ucl_parser_new"].get("brief")
