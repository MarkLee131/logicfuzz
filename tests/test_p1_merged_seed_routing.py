"""P1 — merged-harness seed routing.

A merged UNIFORM/TAIL dispatcher (tools/merge_drivers/merge.py) reads the last
`selector_bytes` of every input as `driverIndex` and routes via
`switch(driverIndex % n)`, feeding `Data[0:Size-selector_bytes]` as the body.
run_extended_fuzzing copied raw seeds verbatim → each seed (a) lost its last
body byte(s) to the selector and (b) routed to a pseudo-random sub-driver, so a
real .icc almost never reached the profile sub-driver. Fix: detect the
dispatcher (`_parse_merged_dispatch`) and tag each raw seed with every
sub-driver's TAIL selector so the format-matching sub-driver gets a clean copy.

The dispatcher fixture is produced by the REAL emitter (SynthesizedDriver) so
the detection regex is tested against exactly what production generates — it
cannot drift from a hand-written copy.
"""
import importlib

ext = importlib.import_module("scripts.run_extended_fuzzing")
from tools.merge_drivers.merge import (  # noqa: E402
    SynthesizedDriver, DispatchMode, SelectorPosition)


class _Stub:
    def __init__(self, path):
        self.fuzz_target_path = str(path)


def _emit_real_merged(tmp_path, n):
    """Write n trivial sub-drivers, synthesize the real merged harness, and
    return (path_to_merged_source, expected_selector_bytes)."""
    srcs = []
    for i in range(n):
        p = tmp_path / f"{i:02d}.fuzz_target"
        p.write_text(
            f"int LLVMFuzzerTestOneInput(const unsigned char *D, unsigned long S)"
            f"{{ (void)D; (void)S; return {i}; }}\n")
        srcs.append(p)
    drv = SynthesizedDriver.from_paths(
        srcs, mode=DispatchMode.UNIFORM, position=SelectorPosition.TAIL,
        weights=None)
    synth = drv.save(tmp_path / "merged")
    entry = next(p for p in synth.glob("entry.*"))
    merged = tmp_path / "99.fuzz_target"
    merged.write_text(entry.read_text())
    return merged, drv.selector_bytes


def test_parse_merged_dispatch_detects_real_emitter_output(tmp_path):
    merged, sb = _emit_real_merged(tmp_path, n=3)
    got = ext.ExtendedFuzzer._parse_merged_dispatch(_Stub(merged))
    assert got == (sb, 3), f"expected (selector_bytes={sb}, n=3), got {got}"


def test_parse_merged_dispatch_detects_larger_n(tmp_path):
    merged, sb = _emit_real_merged(tmp_path, n=10)
    got = ext.ExtendedFuzzer._parse_merged_dispatch(_Stub(merged))
    assert got == (sb, 10), f"expected (selector_bytes={sb}, n=10), got {got}"


def test_parse_merged_dispatch_plain_returns_none(tmp_path):
    f = tmp_path / "01.fuzz_target"
    f.write_text(
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *D, size_t S)'
        '{ (void)D; (void)S; return 0; }')
    assert ext.ExtendedFuzzer._parse_merged_dispatch(_Stub(f)) is None


def test_tagged_seed_routes_clean_body_to_each_subdriver():
    """Dispatcher contract: driverIndex = last k bytes, body = Data[:Size-k].
    A seed tagged `body + d.to_bytes(k,'little')` routes to sub-driver d with
    the ORIGINAL body intact."""
    body = b"acsp-ICC-profile-bytes" * 8
    k, n = 1, 3
    for d in range(n):
        tagged = body + d.to_bytes(k, "little")
        driver_index = int.from_bytes(tagged[len(tagged) - k:], "little")
        assert driver_index % n == d
        assert tagged[: len(tagged) - k] == body  # body intact


def test_untagged_seed_corrupts_body():
    """Document the bug: a raw seed loses its last byte to the selector."""
    body = b"acsp-ICC-profile-bytes" * 8
    assert body[: len(body) - 1] != body
