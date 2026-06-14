"""P0 — preflight runs on the HOST first, retrying inside the OSS-Fuzz
base-runner container ONLY when the host binary fails to LOAD (glibc/ABI
mismatch — the zlib `version GLIBC_2.38 not found` case).

Host-compatible projects (e.g. c-ares, which runs millions of execs/s on the
host) must NEVER be forced into the container — doing so regressed c-ares from
19 accepted preflight drivers to 0 (empty-corpus / entrypoint issues in the
container path). So the container is a strict fallback gated on _is_abi_failure.
"""
import importlib
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Import the real MODULE (not the re-exported function from __init__)
pf = importlib.import_module("tools.merge_drivers.preflight")


def _mk(tmp_path):
    fuzzer_dir = tmp_path / "out"
    fuzzer_dir.mkdir(parents=True)
    fuzzer_binary = fuzzer_dir / "fuzzer"
    fuzzer_binary.write_bytes(b"\x7fELF")
    driver_src = tmp_path / "01.fuzz_target"
    driver_src.write_text("// stub")
    workspace = tmp_path / "ws"
    return driver_src, fuzzer_binary, workspace


def test_host_first_no_container_when_binary_runs(monkeypatch, tmp_path):
    """c-ares case: host run succeeds → container is never invoked."""
    calls = []

    def fake_run(cmd, stdout=None, **kw):
        calls.append(cmd)
        if stdout is not None:
            stdout.write(b"#14600197 DONE cov: 1267 ft: 2000 exec/s: 2433366\n")

        class P:
            returncode = 0

        return P()

    monkeypatch.setattr(pf.subprocess, "run", fake_run)
    monkeypatch.setattr(pf.shutil, "which", lambda _x: "/usr/bin/docker")
    driver_src, fuzzer_binary, workspace = _mk(tmp_path)
    pf._smoke_one(driver_src, fuzzer_binary, 15, workspace, project="c-ares")

    assert calls, "subprocess.run must be called"
    assert calls[0][0] != "docker", "must run on the HOST first"
    assert all(c[0] != "docker" for c in calls), \
        "host binary runs fine → never enter the container"


def test_container_retry_on_abi_failure(monkeypatch, tmp_path):
    """zlib case: host run fails with a glibc loader error → retry in container."""
    calls = []

    def fake_run(cmd, stdout=None, **kw):
        calls.append(cmd)
        if cmd[0] != "docker":
            if stdout is not None:
                stdout.write(b"./fuzzer: /lib/x86_64-linux-gnu/libc.so.6: "
                             b"version `GLIBC_2.38' not found\n")
            rc = 127
        else:
            if stdout is not None:
                stdout.write(b"#2 INITED cov: 5 ft: 10 exec/s: 100\n")
            rc = 0

        class P:
            returncode = rc

        return P()

    monkeypatch.setattr(pf.subprocess, "run", fake_run)
    monkeypatch.setattr(pf.shutil, "which", lambda _x: "/usr/bin/docker")
    driver_src, fuzzer_binary, workspace = _mk(tmp_path)
    pf._smoke_one(driver_src, fuzzer_binary, 15, workspace, project="zlib")

    assert calls[0][0] != "docker", "host first"
    assert any(c[0] == "docker" for c in calls), \
        "must retry in the container on a glibc/ABI load failure"
    dc = [c for c in calls if c[0] == "docker"][0]
    assert "--entrypoint" in dc and any(str(a).startswith("/o/") for a in dc), \
        "container run must use the binary as entrypoint, mounted at /o"
    assert any("base-runner" in str(a) for a in dc)


def test_no_container_without_docker(monkeypatch, tmp_path):
    """Fail-open: no docker on PATH → host run only, even on an ABI failure."""
    calls = []

    def fake_run(cmd, stdout=None, **kw):
        calls.append(cmd)
        if stdout is not None:
            stdout.write(b"version `GLIBC_2.38' not found\n")

        class P:
            returncode = 127

        return P()

    monkeypatch.setattr(pf.subprocess, "run", fake_run)
    monkeypatch.setattr(pf.shutil, "which", lambda _x: None)
    driver_src, fuzzer_binary, workspace = _mk(tmp_path)
    pf._smoke_one(driver_src, fuzzer_binary, 15, workspace, project="zlib")

    assert all(c[0] != "docker" for c in calls), "no docker → host only"


def test_is_abi_failure_unit():
    assert pf._is_abi_failure(127, "version `GLIBC_2.38' not found")
    assert pf._is_abi_failure(1, "error while loading shared libraries: x.so")
    assert not pf._is_abi_failure(0, "anything")        # normal completion
    assert not pf._is_abi_failure(77, "GLIBC_2.38")     # libFuzzer crash, not a load failure
    assert not pf._is_abi_failure(1, "AddressSanitizer: heap-buffer-overflow")
