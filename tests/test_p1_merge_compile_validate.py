"""P1 — compile-validation gate for the merged harness.

First principle: the merge must ship only sub-drivers that COMPILE under the
real OSS-Fuzz build flags. A COMPILE-INVALID candidate (e.g. lcms drivers with
``void name[2]`` void-arrays, undeclared ``cmsSig*`` constants, struct-vs-pointer
mismatch, ``#include "lcms2_internal.h"``) used to slip past preflight (which
only smoke-RUNS drivers that already built a binary) and was then
``|| continue``-skipped + weak-stubbed into a silent no-op slot — the portfolio
lost it and coverage replayed 0.

``tools.merge_drivers.compile_validate.validate_compilable`` compiles each
candidate in the project's OSS-Fuzz container and EXCLUDES the failures; these
tests pin its parsing + fail-open contract (mocking docker — no container) and
the ``run_single_fuzz`` wiring.
"""
import json
from pathlib import Path

import pytest

import run_single_fuzz as rsf
from tools.merge_drivers import compile_validate as cv


class _WD:
    def __init__(self, base):
        self.base = str(base)


class _Bench:
    def __init__(self, project):
        self.project = project


def _mk_sources(tmp_path, names):
    out = []
    for n in names:
        p = tmp_path / n
        p.write_text("int LLVMFuzzerTestOneInput(const unsigned char*x,unsigned long y){return 0;}\n")
        out.append(p)
    return out


# ---- validate_compilable: verdict parsing ----------------------------------

def test_splits_valid_and_invalid(monkeypatch, tmp_path):
    """A container reporting ok/fail per TU → valid kept, failing excluded with
    its diagnostic tail."""
    srcs = _mk_sources(tmp_path, ["01.fuzz_target", "03.fuzz_target",
                                  "05.fuzz_target"])
    monkeypatch.setattr(cv.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(cv, "_ensure_project_image",
                        lambda project: "gcr.io/oss-fuzz/lcms")

    # The container stages candidates as ``NNN_<origname>`` — the verdicts must
    # reference those staged names; build them from the real staging mapping by
    # intercepting _run_container_validation with a function that reads the
    # staged dir.
    def fake_run(image, candidates_dir, project, timeout_sec):
        verdicts = []
        for staged in sorted(Path(candidates_dir).iterdir()):
            ok = "03." not in staged.name  # 03 is the "invalid" one
            err = "" if ok else "03.fuzz_target:67: error: use of undeclared identifier 'cmsSigRGBData'"
            verdicts.append(cv._TuVerdict(name=staged.name, ok=ok, error_tail=err))
        return verdicts

    monkeypatch.setattr(cv, "_run_container_validation", fake_run)
    valid, excluded = cv.validate_compilable(srcs, "lcms")
    valid_names = sorted(p.name for p in valid)
    excl_names = sorted(p.name for p, _ in excluded)
    assert valid_names == ["01.fuzz_target", "05.fuzz_target"]
    assert excl_names == ["03.fuzz_target"]
    assert "cmsSigRGBData" in excluded[0][1]


def test_fail_open_on_infra_failure(monkeypatch, tmp_path):
    """If the container can't run (returns None), keep ALL sources — never block
    a merge on a docker hiccup."""
    srcs = _mk_sources(tmp_path, ["01.fuzz_target", "02.fuzz_target"])
    monkeypatch.setattr(cv.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(cv, "_ensure_project_image",
                        lambda project: "gcr.io/oss-fuzz/lcms")
    monkeypatch.setattr(cv, "_run_container_validation",
                        lambda *a, **k: None)
    valid, excluded = cv.validate_compilable(srcs, "lcms")
    assert sorted(p.name for p in valid) == ["01.fuzz_target", "02.fuzz_target"]
    assert excluded == []


def test_fail_open_when_no_docker(monkeypatch, tmp_path):
    """No docker on PATH → keep all sources."""
    srcs = _mk_sources(tmp_path, ["01.fuzz_target", "02.fuzz_target"])
    monkeypatch.setattr(cv.shutil, "which", lambda _: None)
    valid, excluded = cv.validate_compilable(srcs, "lcms")
    assert len(valid) == 2 and excluded == []


def test_fail_open_when_no_image(monkeypatch, tmp_path):
    """Image can't be obtained → keep all sources."""
    srcs = _mk_sources(tmp_path, ["01.fuzz_target", "02.fuzz_target"])
    monkeypatch.setattr(cv.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(cv, "_ensure_project_image", lambda project: None)
    valid, excluded = cv.validate_compilable(srcs, "lcms")
    assert len(valid) == 2 and excluded == []


def test_keep_unreported_tu(monkeypatch, tmp_path):
    """A candidate the container never reported on is KEPT (fail-open per-TU —
    never drop something we didn't actually vet)."""
    srcs = _mk_sources(tmp_path, ["01.fuzz_target", "02.fuzz_target"])
    monkeypatch.setattr(cv.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(cv, "_ensure_project_image",
                        lambda project: "gcr.io/oss-fuzz/lcms")

    def fake_run(image, candidates_dir, project, timeout_sec):
        # Report on ONLY the first staged candidate.
        staged = sorted(Path(candidates_dir).iterdir())[0]
        return [cv._TuVerdict(name=staged.name, ok=True, error_tail="")]

    monkeypatch.setattr(cv, "_run_container_validation", fake_run)
    valid, excluded = cv.validate_compilable(srcs, "lcms")
    assert sorted(p.name for p in valid) == ["01.fuzz_target", "02.fuzz_target"]
    assert excluded == []


# ---- container-output parser ------------------------------------------------

def test_parser_reads_result_and_error_blocks(monkeypatch, tmp_path):
    """_run_container_validation parses RESULT lines + ERRBEGIN/ERREND blocks."""
    stdout = (
        "EXT_INC= -I/src/lcms/include\n"
        "RESULT ok 000_01.fuzz_target\n"
        "RESULT fail 001_03.fuzz_target\n"
        "ERRBEGIN 001_03.fuzz_target\n"
        "03.fuzz_target:67:83: error: use of undeclared identifier 'cmsSigRGBData'\n"
        "ERREND 001_03.fuzz_target\n"
        "VALIDATE_DONE\n"
    )

    class _P:
        returncode = 0
        def __init__(self):
            self.stdout = stdout
            self.stderr = ""

    monkeypatch.setattr(cv.subprocess, "run", lambda *a, **k: _P())
    verdicts = cv._run_container_validation("img", tmp_path, "lcms", 60)
    assert verdicts is not None
    by_name = {v.name: v for v in verdicts}
    assert by_name["000_01.fuzz_target"].ok is True
    assert by_name["001_03.fuzz_target"].ok is False
    assert "cmsSigRGBData" in by_name["001_03.fuzz_target"].error_tail


def test_parser_fails_open_without_terminator(monkeypatch, tmp_path):
    """No VALIDATE_DONE in output → None (caller fails open)."""
    class _P:
        returncode = 1
        stdout = "RESULT ok 000_01.fuzz_target\n"  # truncated, no terminator
        stderr = "docker: oops"

    monkeypatch.setattr(cv.subprocess, "run", lambda *a, **k: _P())
    assert cv._run_container_validation("img", tmp_path, "lcms", 60) is None


# ---- language-faithfulness (root-cause of a masked C-invalid TU) -----------

def test_validates_in_merge_target_language(monkeypatch, tmp_path):
    """A C-default driver (``.fuzz_target`` with no C++ markers) must be checked
    as C — the language the merge compiles its ``<id>.c`` with — NOT via a
    try-C-then-C++ fallback that would green-light C++-only constructs (e.g.
    ``_cmsContext_struct *`` without the ``struct`` tag)."""
    p = tmp_path / "09.fuzz_target"
    p.write_text("int LLVMFuzzerTestOneInput(const unsigned char*x,unsigned long y){return 0;}\n")
    # IndividualDriver.suffix → 'c' (no C++ markers, .fuzz_target ext).
    assert cv._merge_target_lang(p) == "c"

    captured = {}

    def fake_run(image, candidates_dir, project, timeout_sec):
        captured["langs"] = (Path(candidates_dir) / ".langs").read_text()
        staged = sorted(s for s in Path(candidates_dir).iterdir()
                        if s.name != ".langs")[0]
        return [cv._TuVerdict(name=staged.name, ok=True, error_tail="")]

    monkeypatch.setattr(cv.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(cv, "_ensure_project_image", lambda project: "img")
    monkeypatch.setattr(cv, "_run_container_validation", fake_run)
    cv.validate_compilable([p], "lcms")
    # The per-candidate manifest pins language 'c' for this driver.
    assert captured["langs"].strip().endswith(" c")


def test_cpp_marker_driver_validated_as_cpp(tmp_path):
    """A driver using C++-only syntax resolves to the cpp merge-target lang."""
    p = tmp_path / "drv.fuzz_target"
    p.write_text("#include <vector>\nint LLVMFuzzerTestOneInput(const unsigned char*x,unsigned long y){std::vector<int> v; return 0;}\n")
    assert cv._merge_target_lang(p) == "cpp"


def test_c_compile_promotes_implicit_decl_to_error():
    """The C compile path must re-promote implicit-function-declaration /
    implicit-int to ERRORS — a driver that calls a real library function without
    declaring it only WARNS at compile but fails the merged LINK (undefined
    reference). Pin that the strict flags are applied on the C branch."""
    assert "-Werror=implicit-function-declaration" in cv._VALIDATE_SH
    assert "-Werror=implicit-int" in cv._VALIDATE_SH
    # Strict flags go on the C ($CC) branch, after $CFLAGS (so they override the
    # project's -Wno-error), and the language is read per-candidate from .langs.
    assert "$STRICT_C" in cv._VALIDATE_SH
    assert "/candidates/.langs" in cv._VALIDATE_SH


# ---- run_single_fuzz wiring -------------------------------------------------

def test_wiring_excludes_and_reports(monkeypatch, tmp_path):
    """_compile_validate_candidates drops the invalid TU and writes a report."""
    srcs = _mk_sources(tmp_path, ["01.fuzz_target", "03.fuzz_target"])
    bad = srcs[1]

    def fake_validate(sources, project, **kw):
        good = [s for s in sources if s != bad]
        return good, [(bad, "03: error: undeclared 'cmsSigRGBData'")]

    import tools.merge_drivers.compile_validate as cvmod
    monkeypatch.setattr(cvmod, "validate_compilable", fake_validate)
    out = rsf._compile_validate_candidates(srcs, _Bench("lcms"), _WD(tmp_path))
    assert [p.name for p in out] == ["01.fuzz_target"]
    rep = json.loads((tmp_path / "merged" / "compile_validation.json").read_text())
    assert rep["excluded"][0]["driver"] == "03.fuzz_target"
    assert rep["valid"] == ["01.fuzz_target"]


def test_wiring_skip_env(monkeypatch, tmp_path):
    """LOGICFUZZ_SKIP_COMPILE_VALIDATE → pass-through, no validation."""
    srcs = _mk_sources(tmp_path, ["01.fuzz_target", "02.fuzz_target"])
    monkeypatch.setenv("LOGICFUZZ_SKIP_COMPILE_VALIDATE", "1")

    def boom(*a, **k):  # must NOT be called
        raise AssertionError("validate_compilable called despite skip env")

    import tools.merge_drivers.compile_validate as cvmod
    monkeypatch.setattr(cvmod, "validate_compilable", boom)
    out = rsf._compile_validate_candidates(srcs, _Bench("lcms"), _WD(tmp_path))
    assert out == srcs


def test_wiring_passthrough_without_project(monkeypatch, tmp_path):
    """No benchmark.project → can't pick an image → pass through unchanged."""
    srcs = _mk_sources(tmp_path, ["01.fuzz_target", "02.fuzz_target"])
    out = rsf._compile_validate_candidates(srcs, _Bench(None), _WD(tmp_path))
    assert out == srcs
