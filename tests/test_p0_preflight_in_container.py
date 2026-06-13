"""P0 — preflight smoke runs inside the OSS-Fuzz base-runner container.

Regression test for the GLIBC version mismatch: fuzz binaries are built
inside Docker (glibc 2.38) but the host may only have glibc 2.35, causing
`version GLIBC_2.38 not found` → binary_broken false-positive on every
zlib driver.  Fix: when docker is available and a project name is given,
_smoke_one wraps the run in `docker run gcr.io/oss-fuzz-base/base-runner`.
"""
import importlib
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Import the real MODULE (not the re-exported function from __init__)
pf = importlib.import_module("tools.merge_drivers.preflight")


def test_smoke_cmd_runs_in_container(monkeypatch, tmp_path):
    """_smoke_one uses 'docker run base-runner' when docker is available + project given."""
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class P:
            returncode = 0
        return P()

    monkeypatch.setattr(pf.subprocess, "run", fake_run)
    monkeypatch.setattr(pf.shutil, "which", lambda x: "/usr/bin/docker")

    # Build a minimal workspace as _smoke_one expects:
    # it creates corpus_dir / crashes_dir / log_file inside workspace itself.
    workspace = tmp_path / "ws"
    workspace.mkdir()

    # Create a fake fuzzer binary in a parent dir so the mount resolves
    fuzzer_dir = tmp_path / "out"
    fuzzer_dir.mkdir(parents=True)
    fuzzer_binary = fuzzer_dir / "zlib_fuzzer"
    fuzzer_binary.write_bytes(b"\x7fELF")

    # Create a fake driver source path (just needs to exist for the call)
    driver_src = tmp_path / "03.fuzz_target"
    driver_src.write_text("// stub")

    pf._smoke_one(driver_src, fuzzer_binary, 15, workspace, project="zlib")

    cmd = captured["cmd"]
    assert cmd[0] == "docker", f"expected docker as first element, got: {cmd}"
    assert "run" in cmd[:3], f"expected 'run' in first 3 elements, got: {cmd[:3]}"
    assert any("base-runner" in str(a) for a in cmd), (
        f"must use base-runner image; cmd was: {cmd}"
    )
    # Pin the two subtle parts of the invocation: the binary is the entrypoint
    # (mounted at /o) and the corpus mount is present.
    assert "--entrypoint" in cmd, f"must set --entrypoint; cmd was: {cmd}"
    assert any(str(a).startswith("/o/") for a in cmd), (
        f"binary must be mounted+run from /o; cmd was: {cmd}"
    )
    assert any("/o:ro" in str(a) for a in cmd), (
        f"binary dir must be mounted read-only at /o; cmd was: {cmd}"
    )


def test_smoke_cmd_falls_back_to_host_when_no_docker(monkeypatch, tmp_path):
    """Without docker, _smoke_one runs the binary directly on the host."""
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class P:
            returncode = 0
        return P()

    monkeypatch.setattr(pf.subprocess, "run", fake_run)
    # docker not available
    monkeypatch.setattr(pf.shutil, "which", lambda x: None)

    workspace = tmp_path / "ws"
    workspace.mkdir()
    fuzzer_binary = tmp_path / "out" / "zlib_fuzzer"
    fuzzer_binary.parent.mkdir()
    fuzzer_binary.write_bytes(b"\x7fELF")
    driver_src = tmp_path / "03.fuzz_target"
    driver_src.write_text("// stub")

    pf._smoke_one(driver_src, fuzzer_binary, 15, workspace, project="zlib")

    cmd = captured["cmd"]
    assert cmd[0] != "docker", f"should fall back to host cmd, got: {cmd}"
    assert str(fuzzer_binary) == cmd[0], (
        f"host fallback should run the binary directly; got: {cmd}"
    )


def test_smoke_cmd_falls_back_when_no_project(monkeypatch, tmp_path):
    """With docker available but no project given, falls back to host run."""
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class P:
            returncode = 0
        return P()

    monkeypatch.setattr(pf.subprocess, "run", fake_run)
    monkeypatch.setattr(pf.shutil, "which", lambda x: "/usr/bin/docker")

    workspace = tmp_path / "ws"
    workspace.mkdir()
    fuzzer_binary = tmp_path / "out" / "zlib_fuzzer"
    fuzzer_binary.parent.mkdir()
    fuzzer_binary.write_bytes(b"\x7fELF")
    driver_src = tmp_path / "03.fuzz_target"
    driver_src.write_text("// stub")

    # project="" → no docker wrap
    pf._smoke_one(driver_src, fuzzer_binary, 15, workspace, project="")

    cmd = captured["cmd"]
    assert cmd[0] != "docker", f"should fall back (no project), got: {cmd}"
