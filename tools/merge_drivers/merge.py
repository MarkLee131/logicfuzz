"""Merge N libFuzzer drivers into one dispatching mega-harness.

Multi-TU layout (per PromeFuzz ``synthesize_into_one``):

    1. For each input driver ``d_i``:
         - Read the source as-is.
         - Rewrite ``LLVMFuzzerTestOneInput(`` → ``LLVMFuzzerTestOneInput_<id>(``.
         - Write to ``synthesized/<id>.{c,cpp}`` — each stays its own
           translation unit, so ``static`` helpers / typedefs / macros in
           one driver cannot collide with another at link time.
    2. Emit ``synthesized/entry.{c,cpp}``: forward-declare every
       ``LLVMFuzzerTestOneInput_<id>``, read a ``selector_bytes``-wide
       prefix from ``Data``, modulo to ``N``, dispatch.
    3. Emit ``oss_fuzz_build_snippet.sh`` that compiles
       ``synthesized/*.{c,cpp}`` under the OSS-Fuzz build environment
       (``$CC``, ``$CFLAGS``, ``$LIB_FUZZING_ENGINE``, ``$WORK``,
       ``$OUT``). The snippet is meant to be appended to the OSS-Fuzz
       project's ``build.sh``.

Why multi-TU rather than single-file flattening: when two drivers each
declare ``static int compare(...)`` or include the same header that
defines macros, single-file flattening either link-fails or requires
heroic identifier rewriting. Independent TUs let the linker handle it.
We only need the public symbol ``LLVMFuzzerTestOneInput`` to be unique
across TUs — that's why we rename it.

References: PromeFuzz § ``synthesize_into_one`` (CCS'25).
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from pathlib import Path
from typing import List, Optional, Sequence


class DispatchMode(str, Enum):
    """How sub-driver indices are derived from selector bytes.

    UNIFORM: ``idx = selector % N`` (PromeFuzz default). Each sub-driver
        gets ~1/N of the fuzz budget regardless of marginal coverage.
    CDF: a 16-bit selector is binary-searched against a precomputed
        threshold table; sub-driver ``i`` gets a fraction of the
        selector space proportional to its weight ``w_i`` (typically
        marginal-coverage from O2 selection). Heavier sub-drivers get
        more fuzz budget.
    """
    UNIFORM = "uniform"
    CDF = "cdf"


class SelectorPosition(str, Enum):
    """Where in the input the dispatch selector lives.

    HEAD: ``Data[0..k]`` — PromeFuzz default. Selector mutates with
        every prefix-biased mutator op; sub-harness body bytes shift
        meaning whenever the selector flips.
    TAIL: ``Data[Size-k..Size]`` — selector mutated less often by
        prefix-biased mutators, so the body is (locally) stable for
        intra-sub-harness exploration. Cross-sub-harness migration
        still happens via tail mutation but at lower frequency. This
        biases the implicit scheduler toward "deep-fuzz one sub-harness
        at a time" rather than "round-robin every fuzz step".
    """
    HEAD = "head"
    TAIL = "tail"


_LLVMFUZZ_RE = re.compile(
    r'\bLLVMFuzzerTestOneInput\s*\('
)


_C_SUFFIXES = {"c"}
_CPP_SUFFIXES = {"cc", "cpp", "cxx", "C"}


@dataclass
class IndividualDriver:
    """One sub-harness extracted from an input ``.fuzz_target`` file."""

    driver_path: Path
    index: int  # 0-based position in the synthesized driver list

    @cached_property
    def driver_id(self) -> str:
        """Stable id derived from the source filename.

        ``01.fuzz_target`` → ``01``. ``fuzz_driver_3.cpp`` → ``3``.
        Falls back to the zero-padded index if no digits are found.
        """
        stem = self.driver_path.stem  # "01" from "01.fuzz_target"
        if stem.isdigit():
            return stem
        m = re.search(r'(\d+)', stem)
        if m:
            return m.group(1)
        return f"{self.index:02d}"

    @cached_property
    def suffix(self) -> str:
        """Effective C/C++ suffix.

        Order of precedence:

        1. Real file extension (``.c`` / ``.cpp`` / ``.cc`` / ``.cxx``).
        2. Generic ``.fuzz_target`` etc. — content sniff for C++-only
           syntax: ``std::``, ``class ``, ``template<``, ``namespace ``,
           ``nullptr``, ``new ``, ``delete `` outside strings.
           Note: ``extern "C"`` does NOT imply C++ — it's standard
           C/C++ portability boilerplate when guarded by
           ``#ifdef __cplusplus``.
        3. Default C.
        """
        ext = self.driver_path.suffix.lstrip(".")
        if ext in _C_SUFFIXES:
            return "c"
        if ext in _CPP_SUFFIXES:
            return "cpp"
        # Strip C/C++ comments so we don't pick up false positives from
        # comments like ``// Internet class``.
        text = self.content
        text_no_block = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        text_stripped = re.sub(r'//[^\n]*', '', text_no_block)
        cpp_markers = (
            r'\bstd::',
            r'\btemplate\s*<',
            r'\bnullptr\b',
            r'\bclass\s+\w+\s*[:{\(]',     # class declaration / inheritance
            r'\bnamespace\s+\w+\s*\{',     # namespace block
        )
        if any(re.search(p, text_stripped) for p in cpp_markers):
            return "cpp"
        return "c"

    @cached_property
    def is_cpp(self) -> bool:
        return self.suffix == "cpp"

    @cached_property
    def content(self) -> str:
        return self.driver_path.read_text(encoding="utf-8", errors="replace")

    @cached_property
    def renamed_function(self) -> str:
        return f"LLVMFuzzerTestOneInput_{self.driver_id}"

    def modified_content(self, total_drivers: int) -> str:
        """Source with the public symbol renamed.

        We only rename the *function symbol* (the call site that the
        fuzzer engine invokes). Local helpers, statics, typedefs are
        untouched — they're already isolated by being in a separate TU.
        """
        del total_drivers  # reserved for future per-driver guard macros
        new = _LLVMFUZZ_RE.sub(f"{self.renamed_function}(", self.content)
        if new == self.content:
            raise ValueError(
                f"{self.driver_path}: no LLVMFuzzerTestOneInput found"
            )
        return new


# ---------------------------------------------------------------- entry emit


def _selector_bytes(driver_count: int) -> int:
    """Bytes needed to index ``driver_count`` sub-drivers without mod bias.

    ``ceil(log2(N) / 8)``. ``N=1`` is degenerate but we still allocate
    one byte to keep ``Data + offset`` well-defined.
    """
    bits = max(driver_count - 1, 1).bit_length()
    return max((bits + 7) // 8, 1)


_CDF_SELECTOR_BITS = 16  # fixed-width 16-bit CDF selector regardless of N


def _compute_cdf_thresholds(weights: Sequence[float]) -> List[int]:
    """Build a uint16 CDF threshold table from per-driver weights.

    ``threshold[i]`` is the *upper bound* of selector values mapped to
    sub-driver ``i``: an input ``s`` satisfies ``s < threshold[i]`` iff
    ``i`` is the first index with cumulative weight covering ``s``.

    The last threshold is forced to ``2**16`` so an extreme selector
    (e.g. all 0xFF bytes) still maps somewhere. Zero-weight drivers
    keep their predecessor's threshold (they get no slot — caller
    should have filtered them out before reaching here).

    Returns a list of length ``len(weights)``.
    """
    if not weights:
        return []
    total = float(sum(max(w, 0.0) for w in weights))
    if total <= 0.0:
        # Degenerate: fall back to uniform CDF.
        n = len(weights)
        thresholds = [
            int(round((i + 1) * 65535 / n))
            for i in range(n)
        ]
        thresholds[-1] = 65535
        return thresholds
    thresholds = []
    cum = 0.0
    for i, w in enumerate(weights):
        cum += max(w, 0.0)
        # Map cumulative fraction to 16-bit selector space. The last
        # entry is sentinel-only (the lookup loop exits on idx+1 < N
        # before reading it), but we cap at 65535 to keep the table
        # uint16-clean.
        t = int(round(cum / total * 65535))
        if i == len(weights) - 1:
            t = 65535
        # Ensure monotonic non-decreasing (rounding may otherwise let
        # consecutive thresholds collide; that's fine — a zero-width
        # bucket simply means the lookup loop walks past it).
        if thresholds and t < thresholds[-1]:
            t = thresholds[-1]
        thresholds.append(t)
    return thresholds


_PREAMBLE = """\
// Auto-generated by tools/merge_drivers/merge.py — do not edit.
//
// Multi-task fuzz harness: {n} sub-drivers share one binary + corpus.
//   dispatch  : {mode}
//   selector  : {selector_bytes} byte(s) at {position}
//
// Sub-driver mapping (for crash triage):
{harness_map}
//
// References: PromeFuzz (CCS'25) ``synthesize_into_one``;
//   selector at tail follows the multi-task fuzzing observation that
//   prefix-biased mutators destabilize body semantics if selector
//   sits at offset 0. Khuller/Moss/Naor 1999 motivates the CDF
//   weight assignment via marginal-coverage greedy.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

{declarations}
"""


_ENTRY_BODY_UNIFORM = """\
{cpp_open}
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Size < {selector_bytes} + 1) {{
        return 0;
    }}
    unsigned int driverIndex = 0;
{selector_read}
    switch (driverIndex % {n}) {{
{cases}
        default:
            return 0;
    }}
}}
{cpp_close}
"""


_ENTRY_BODY_CDF = """\
static const unsigned short merged_cdf_threshold[{n}] = {{
{thresholds}
}};

{cpp_open}
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Size < 2 + 1) {{
        return 0;
    }}
    unsigned short selector = 0;
{selector_read}
    unsigned int idx = 0;
    while (idx + 1 < {n} && selector >= merged_cdf_threshold[idx]) {{
        ++idx;
    }}
    switch (idx) {{
{cases}
        default:
            return 0;
    }}
}}
{cpp_close}
"""


@dataclass
class SynthesizedDriver:
    """The merged dispatching harness.

    ``weights`` is required for ``DispatchMode.CDF`` and ignored for
    ``UNIFORM``. It must be the same length as ``drivers`` and align
    positionally — ``weights[i]`` is sub-driver ``drivers[i]``'s
    weight. Typically supplied as marginal-coverage from
    ``select.select_top_k``.
    """

    drivers: List[IndividualDriver]
    mode: DispatchMode = DispatchMode.UNIFORM
    position: SelectorPosition = SelectorPosition.TAIL
    weights: Optional[List[float]] = None

    @classmethod
    def from_paths(
        cls,
        paths: List[Path],
        mode: DispatchMode = DispatchMode.UNIFORM,
        position: SelectorPosition = SelectorPosition.TAIL,
        weights: Optional[List[float]] = None,
    ) -> "SynthesizedDriver":
        sorted_paths = sorted(paths, key=lambda p: p.name)
        drivers = [IndividualDriver(p, i) for i, p in enumerate(sorted_paths)]
        if not drivers:
            raise ValueError("no input drivers")
        # Reject duplicate ids (would collide on the renamed symbol)
        seen: dict[str, Path] = {}
        for d in drivers:
            if d.driver_id in seen:
                raise ValueError(
                    f"duplicate driver_id {d.driver_id!r}: "
                    f"{seen[d.driver_id]} and {d.driver_path}"
                )
            seen[d.driver_id] = d.driver_path
        return cls(
            drivers=drivers,
            mode=mode,
            position=position,
            weights=weights,
        )

    def __post_init__(self) -> None:
        if self.mode == DispatchMode.CDF:
            if self.weights is None:
                raise ValueError("DispatchMode.CDF requires weights")
            if len(self.weights) != len(self.drivers):
                raise ValueError(
                    f"weights length {len(self.weights)} != "
                    f"drivers length {len(self.drivers)}"
                )

    @cached_property
    def driver_count(self) -> int:
        return len(self.drivers)

    @cached_property
    def is_cpp(self) -> bool:
        return any(d.is_cpp for d in self.drivers)

    @cached_property
    def selector_bytes(self) -> int:
        if self.mode == DispatchMode.CDF:
            return _CDF_SELECTOR_BITS // 8  # 2
        return _selector_bytes(self.driver_count)

    @cached_property
    def entry_suffix(self) -> str:
        return "cpp" if self.is_cpp else "c"

    def _emit_selector_read(self) -> str:
        """Emit the ``memcpy`` reading the selector + body slicing.

        Body slicing variables ``remainData`` / ``remainSize`` (uniform)
        or ``bodyData`` / ``bodySize`` (cdf) are declared as ``const
        uint8_t *`` / ``size_t``. Uniform uses the legacy variable
        names so existing unit tests / inspections stay readable.
        """
        sb = self.selector_bytes
        if self.mode == DispatchMode.UNIFORM:
            if self.position == SelectorPosition.HEAD:
                return (
                    f"    memcpy(&driverIndex, Data, {sb});\n"
                    f"    const uint8_t *remainData = Data + {sb};\n"
                    f"    size_t remainSize = Size - {sb};"
                )
            return (
                f"    memcpy(&driverIndex, Data + Size - {sb}, {sb});\n"
                f"    const uint8_t *remainData = Data;\n"
                f"    size_t remainSize = Size - {sb};"
            )
        # CDF — selector_bytes == 2
        if self.position == SelectorPosition.HEAD:
            return (
                f"    memcpy(&selector, Data, 2);\n"
                f"    const uint8_t *bodyData = Data + 2;\n"
                f"    size_t bodySize = Size - 2;"
            )
        return (
            f"    memcpy(&selector, Data + Size - 2, 2);\n"
            f"    const uint8_t *bodyData = Data;\n"
            f"    size_t bodySize = Size - 2;"
        )

    def emit_entry(self) -> str:
        n = self.driver_count
        decl_prefix = 'extern "C" ' if self.is_cpp else ""
        # Emit a __weak DEFAULT DEFINITION (not a forward decl) per sub-driver:
        # when the driver's TU compiles, its STRONG definition overrides this
        # stub; when the TU was skipped (non-compiling → no object, see
        # emit_oss_fuzz_build_snippet), the weak stub provides the symbol so the
        # link still succeeds and that slot is a harmless no-op.
        declarations = "\n".join(
            f'{decl_prefix}__attribute__((weak)) int {d.renamed_function}'
            f'(const uint8_t *Data, size_t Size) '
            f'{{ (void)Data; (void)Size; return 0; }}'
            for d in self.drivers
        )
        body_var = "remainData" if self.mode == DispatchMode.UNIFORM else "bodyData"
        size_var = "remainSize" if self.mode == DispatchMode.UNIFORM else "bodySize"
        cases = "\n".join(
            f"        case {i}:\n"
            f"            return {d.renamed_function}({body_var}, {size_var});"
            for i, d in enumerate(self.drivers)
        )
        weight_note = ""
        if self.mode == DispatchMode.CDF and self.weights:
            weight_note = " (weights: " + ", ".join(
                f"{w:.0f}" for w in self.weights
            ) + ")"
        harness_map = "\n".join(
            f"// case {i:>3}: {d.driver_path.name} → {d.renamed_function}"
            + (f"  w={self.weights[i]:.0f}"
               if self.mode == DispatchMode.CDF and self.weights
               else "")
            for i, d in enumerate(self.drivers)
        )
        cpp_open = 'extern "C" {' if self.is_cpp else ""
        cpp_close = "}" if self.is_cpp else ""

        preamble = _PREAMBLE.format(
            n=n,
            mode=f"{self.mode.value}{weight_note}",
            selector_bytes=self.selector_bytes,
            position=self.position.value,
            harness_map=harness_map,
            declarations=declarations,
        )

        if self.mode == DispatchMode.UNIFORM:
            body = _ENTRY_BODY_UNIFORM.format(
                n=n,
                selector_bytes=self.selector_bytes,
                selector_read=self._emit_selector_read(),
                cases=cases,
                cpp_open=cpp_open,
                cpp_close=cpp_close,
            )
        else:
            assert self.weights is not None  # post_init validated
            thresholds = _compute_cdf_thresholds(self.weights)
            threshold_lines = ",\n".join(
                f"    {t}u" for t in thresholds
            )
            body = _ENTRY_BODY_CDF.format(
                n=n,
                thresholds=threshold_lines,
                selector_read=self._emit_selector_read(),
                cases=cases,
                cpp_open=cpp_open,
                cpp_close=cpp_close,
            )

        return preamble + "\n" + body

    def emit_oss_fuzz_build_snippet(
        self,
        target_name: str = "synthesized_fuzzer",
        extra_libs: str = "",
        extra_includes: str = "",
        synth_dir_var: str = "$SRC/synthesized",
    ) -> str:
        """A bash snippet to append to the OSS-Fuzz project's ``build.sh``.

        Compiles each ``synthesized/*.{c,cpp}`` separately (so each TU
        sees its own headers, not the union), then links the objects
        plus ``$LIB_FUZZING_ENGINE`` and any project libs into
        ``$OUT/<target_name>``.

        ``extra_libs`` and ``extra_includes`` are passed verbatim — caller
        is responsible for matching the project's existing link line.
        """
        # A non-compiling sub-driver must NOT kill the whole merged build:
        # skip it (produce no .o, continue the loop). Its symbol is still
        # provided by the weak stub in entry.{c,cpp}, so the link succeeds
        # and the slot becomes a harmless no-op.
        c_compile = (
            f'  $CC $CFLAGS {extra_includes} -c "$src" -o "$obj" '
            f'|| {{ echo "merged: skip non-compiling $src"; continue; }}\n'
        )
        cpp_compile = (
            f'  $CXX $CXXFLAGS {extra_includes} -c "$src" -o "$obj" '
            f'|| {{ echo "merged: skip non-compiling $src"; continue; }}\n'
        )
        per_file = (
            f'for src in {synth_dir_var}/*.c {synth_dir_var}/*.cpp '
            f'{synth_dir_var}/*.cc {synth_dir_var}/*.cxx; do\n'
            f'  [ -e "$src" ] || continue\n'
            f'  obj="$WORK/synth_$(basename "$src").o"\n'
            f'  case "$src" in\n'
            f'    *.c)\n{c_compile}'
            f'      ;;\n'
            f'    *.cc|*.cpp|*.cxx)\n{cpp_compile}'
            f'      ;;\n'
            f'  esac\n'
            f'done\n'
        )
        link_compiler = "$CXX $CXXFLAGS" if self.is_cpp else "$CC $CFLAGS"
        # libFuzzer's runtime is C++; if any sub-driver is C++ we must
        # link with $CXX. If all are C we still link with $CC because
        # $LIB_FUZZING_ENGINE handles the C++ runtime itself on OSS-Fuzz.
        link_line = (
            f'{link_compiler} $WORK/synth_*.o '
            f'-o $OUT/{target_name} '
            f'$LIB_FUZZING_ENGINE {extra_libs}'
        )
        return (
            "\n# ===== merged fuzz harness "
            f"({self.driver_count} sub-drivers, "
            "tools/merge_drivers) =====\n"
            f"{per_file}"
            f"{link_line}\n"
            "# ===== end merged fuzz harness =====\n"
        )

    def save(self, output_dir: Path) -> Path:
        """Write the synthesized layout under ``output_dir``.

        Returns the synthesized source directory (``output_dir/synthesized``).
        """
        output_dir = output_dir.resolve()
        synth_dir = output_dir / "synthesized"
        if synth_dir.exists():
            shutil.rmtree(synth_dir)
        synth_dir.mkdir(parents=True)

        # Per-driver TUs
        for d in self.drivers:
            tu_path = synth_dir / f"{d.driver_id}.{d.suffix}"
            tu_path.write_text(d.modified_content(self.driver_count))

        # Entry dispatcher
        entry_path = synth_dir / f"entry.{self.entry_suffix}"
        entry_path.write_text(self.emit_entry())

        # Build snippet (default — caller can re-emit with their libs)
        snippet_path = output_dir / "oss_fuzz_build_snippet.sh"
        snippet_path.write_text(self.emit_oss_fuzz_build_snippet())

        return synth_dir


