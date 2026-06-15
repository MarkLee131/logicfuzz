"""LeakSanitizer cannot run under the ptrace-restricted container/host used for
fuzzing here: at process exit it raises "LeakSanitizer has encountered a fatal
error" and libFuzzer records the (empty) current unit as a crash artifact. This
marks EVERY driver as crashed and adds per-child abort overhead in fork-mode long
runs. The libFuzzer ``-detect_leaks=0`` CLI flag does NOT suppress the runtime's
atexit LSan check; only the ASAN_OPTIONS environment variable does. These tests
pin the helper that builds a fuzzing subprocess env / container -e args with
``detect_leaks=0`` while preserving any pre-existing ASAN_OPTIONS keys.
"""
from experiment.asan_env import asan_options_value, fuzzing_subprocess_env


def test_adds_detect_leaks_zero_when_absent():
    val = asan_options_value("")
    assert "detect_leaks=0" in val.split(":")


def test_preserves_existing_options():
    val = asan_options_value("allocator_may_return_null=1:handle_abort=2")
    parts = val.split(":")
    assert "allocator_may_return_null=1" in parts
    assert "handle_abort=2" in parts
    assert "detect_leaks=0" in parts


def test_overrides_existing_detect_leaks_one():
    val = asan_options_value("detect_leaks=1:foo=bar")
    parts = val.split(":")
    assert "detect_leaks=0" in parts
    assert "detect_leaks=1" not in parts
    assert "foo=bar" in parts


def test_no_duplicate_detect_leaks():
    val = asan_options_value("detect_leaks=0")
    assert val.split(":").count("detect_leaks=0") == 1


def test_subprocess_env_sets_asan_options_and_preserves_path():
    base = {"PATH": "/usr/bin", "ASAN_OPTIONS": "handle_segv=1"}
    env = fuzzing_subprocess_env(base)
    assert env["PATH"] == "/usr/bin"
    parts = env["ASAN_OPTIONS"].split(":")
    assert "detect_leaks=0" in parts
    assert "handle_segv=1" in parts
    # original dict not mutated
    assert base["ASAN_OPTIONS"] == "handle_segv=1"
