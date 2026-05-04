"""Multi-task fuzz harness merger.

Folds N independent ``LLVMFuzzerTestOneInput`` drivers into a single binary
that dispatches by a leading selector word (PromeFuzz ``synthesize_into_one``
style, multi-TU layout — each sub-driver stays in its own translation unit
to avoid identifier collisions).

Layout produced under ``--output``::

    synthesized/
        entry.{c,cpp}         # dispatcher
        <id>.{c,cpp}          # sub-driver i with LLVMFuzzerTestOneInput → ..._i
    oss_fuzz_build_snippet.sh # to append to the OSS-Fuzz project build.sh
    preflight_report.json     # if pre-flight ran (--preflight)

Theory anchor: multi-task fuzzing as disjoint union of sub-language acceptors
with a discriminator word. The fuzzer's mutator implicitly schedules across
sub-harnesses — improving an input for harness A transfers to B with a
single-byte mutation of the selector. PromeFuzz adopted this in CCS'25; we
adopt the same multi-TU structural approach (correct-by-construction wrt
collisions) and add an O1 pre-flight pass to drop drivers that crash on
empty input or fail to gain edges in 15 s.

Public entry points::

    from tools.merge_drivers.merge import SynthesizedDriver, IndividualDriver
    from tools.merge_drivers.preflight import preflight, PreflightResult
"""

from tools.merge_drivers.merge import (
    DispatchMode,
    IndividualDriver,
    SelectorPosition,
    SynthesizedDriver,
)
from tools.merge_drivers.preflight import PreflightResult, preflight
from tools.merge_drivers.select import (
    DriverCoverage,
    SelectionResult,
    SelectionStep,
    select_top_k,
)
from tools.merge_drivers.corpus import CorpusUnionStats, union_corpus

__all__ = [
    "IndividualDriver",
    "SynthesizedDriver",
    "DispatchMode",
    "SelectorPosition",
    "PreflightResult",
    "preflight",
    "DriverCoverage",
    "SelectionStep",
    "SelectionResult",
    "select_top_k",
    "CorpusUnionStats",
    "union_corpus",
]
