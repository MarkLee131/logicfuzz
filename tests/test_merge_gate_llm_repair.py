"""Merge-gate LLM repair (Direction 1): recover non-compiling drivers that the
merge-stage compile-validation gate would otherwise SILENTLY DROP.

The merge gate (tools/merge_drivers/compile_validate.validate_compilable) compiles
each candidate under the stricter OSS-Fuzz coverage-build flags and EXCLUDES every
TU that fails — with no repair. Measured loss: libpng 34/110 excluded, ~all
mechanical C-vs-C++ fixes ("must use 'struct' tag", undeclared identifier). This
module gives each excluded TU ONE single-shot LLM rewrite, then RE-VALIDATES it
through the SAME gate and keeps it only if it now compiles (fail-closed → A≡B is
preserved: a kept TU compiles identically in the address + coverage builds).

Pure + dependency-injected (llm_query, revalidate) so it is unit-testable with no
docker and no real LLM.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.merge_drivers import llm_repair
from tools.merge_drivers.llm_repair import _extract_fuzz_target


# --- _extract_fuzz_target: robust to the common markdown-instead-of-tag variant --

def test_extract_prefers_fuzz_target_tag():
    resp = "<fuzz_target>int LLVMFuzzerTestOneInput(){return 0;}</fuzz_target>\n```c\nWRONG\n```"
    assert "LLVMFuzzerTestOneInput" in _extract_fuzz_target(resp)
    assert "WRONG" not in _extract_fuzz_target(resp)


def test_extract_markdown_fallback_when_no_tag():
    # gpt-4o often returns a ```c block instead of the <fuzz_target> tag — recover
    # it when it's clearly a fuzz target (has LLVMFuzzerTestOneInput). Measured: 3
    # of nghttp2's 8 repair attempts failed ONLY on this format gap.
    resp = ("Here's the corrected driver:\n```cpp\n"
            "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){ return 0; }\n```\n")
    code = _extract_fuzz_target(resp)
    assert "LLVMFuzzerTestOneInput" in code
    assert "```" not in code and "Here's" not in code


def test_extract_ignores_non_driver_markdown():
    # a markdown block that is NOT a fuzz target (no entrypoint) must not be taken
    assert _extract_fuzz_target("```sh\nrm -rf /tmp/x\n```") == ""
    assert _extract_fuzz_target("I can't help with that.") == ""


def _write(p, text):
    p.write_text(text)
    return p


# --- build_repair_prompt: deterministic, carries error + language + triage hint --

def test_prompt_carries_error_language_and_source():
    src = "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){BufState x;return 0;}"
    err = "fuzz.c:1:1: error: must use 'struct' tag to refer to type 'BufState'"
    prompt = llm_repair.build_repair_prompt(src, err, lang="c")
    assert "BufState" in prompt           # the compiler diagnostic is present
    assert err in prompt
    assert src in prompt                  # the source to repair is present
    # language is stated so the LLM does not re-introduce C++-only syntax
    assert "C" in prompt and "c++" not in prompt.lower().split("language")[0][-40:]
    # deterministic triage guidance for the struct-tag class is injected
    assert "struct" in prompt.lower()
    # the LLM is told to emit a <fuzz_target> block (so parse_tag can read it)
    assert "<fuzz_target>" in prompt


# --- repair_candidates: happy path recovers a TU that re-validates ----------------

def test_recovers_when_rewrite_revalidates(tmp_path):
    bad = _write(tmp_path / "07.fuzz_target", "BAD struct tag code")  # excluded
    excluded = [(bad, "error: must use 'struct' tag to refer to type 'BufState'")]
    out_dir = tmp_path / "repaired"

    def fake_llm(_prompt):
        return "<fuzz_target>GOOD struct BufState code</fuzz_target>"

    def fake_revalidate(sources, project, iquote_dirs=None):
        # mirrors validate_compilable's contract: (valid, excluded)
        valid = [s for s in sources if "GOOD" in pathlib.Path(s).read_text()]
        excl = [(s, "still bad") for s in sources if s not in valid]
        return valid, excl

    recovered, still = llm_repair.repair_candidates(
        excluded, project="libpng", llm_query=fake_llm, out_dir=out_dir,
        revalidate=fake_revalidate)

    assert len(recovered) == 1 and len(still) == 0
    orig, repaired = recovered[0]
    assert orig == bad
    assert "GOOD" in repaired.read_text()
    assert repaired.suffix == bad.suffix      # merge-target language preserved


# --- repair_candidates: fail-closed when the rewrite still does not compile -------

def test_fail_closed_when_revalidate_still_fails(tmp_path):
    bad = _write(tmp_path / "07.fuzz_target", "BAD")
    excluded = [(bad, "error: expected identifier")]
    out_dir = tmp_path / "repaired"

    def fake_llm(_prompt):
        return "<fuzz_target>STILL BROKEN</fuzz_target>"

    def fake_revalidate(sources, project, iquote_dirs=None):
        return [], [(s, "error: expected identifier") for s in sources]

    recovered, still = llm_repair.repair_candidates(
        excluded, project="libpng", llm_query=fake_llm, out_dir=out_dir,
        revalidate=fake_revalidate)

    assert len(recovered) == 0
    assert len(still) == 1 and still[0][0] == bad


# --- repair_candidates: fail-closed when the LLM emits no <fuzz_target> -----------

def test_fail_closed_when_no_fuzz_target_tag(tmp_path):
    bad = _write(tmp_path / "07.fuzz_target", "BAD")
    excluded = [(bad, "error: expected expression")]
    out_dir = tmp_path / "repaired"

    revalidate_calls = []

    def fake_llm(_prompt):
        return "I cannot help with that."   # no <fuzz_target> block

    def fake_revalidate(sources, project, iquote_dirs=None):
        revalidate_calls.append(list(sources))
        return list(sources), []

    recovered, still = llm_repair.repair_candidates(
        excluded, project="libpng", llm_query=fake_llm, out_dir=out_dir,
        revalidate=fake_revalidate)

    assert len(recovered) == 0
    assert len(still) == 1
    # a no-output TU is never sent to re-validation (nothing to validate)
    assert revalidate_calls == [] or all(not c for c in revalidate_calls)
