"""Root cause of the merged-driver-count collapse (2026-06-16, systematic-debugging).

A trial that COMPILES but CRASHES during the optimization-phase fuzz run gets an
``AnalysisResult`` appended as its FINAL result (``state_to_result_history`` adds
it whenever a crash verdict exists). ``AnalysisResult.__init__`` has no ``compiles``
parameter, so its ``compiles`` is the ``Result`` default (False) — even though it
wraps a ``run_result`` that DID compile. The merge selects
``best_result = result_history[-1]`` (that AnalysisResult) and drops any candidate
where ``not best_result.compiles`` → compiled-but-crashed drivers are excluded from
the merge BEFORE preflight can vet them.

Impact (lcms breadth run): 63 trials built good binaries, but 83 execution crashes
→ ~48 became AnalysisResult-tailed → only 15 reached preflight → 14 merged → 883
edges (vs fix1a's 61 drivers → 2092). Deep drivers crash more on random input, so
they are hit hardest. The fix: the AnalysisResult of a compiled driver must report
``compiles=True`` (propagate the trial's compile status), so preflight — not this
filter — decides whether a crashing driver is mergeable.
"""
import tempfile

from experiment.benchmark import Benchmark
from experiment.workdir import WorkDirs
from src.workflow.adapters import StateAdapter
from results import AnalysisResult


def _state_with_crash(compile_success: bool):
    wd = WorkDirs(tempfile.mkdtemp(), keep=True)
    b = Benchmark('lcms-test', 'lcms', 'c', '', 'cms_gdb_fuzzer', 'int',
                  [], '/src/cms_gdb_fuzzer.c')
    return {
        'benchmark': b.to_dict(),
        'work_dirs': wd.to_dict(),
        'trial': 7,
        'fuzz_target_source': 'int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){return 0;}',
        'build_script_source': '',
        'compile_success': compile_success,
        'binary_exists': True,
        'is_function_referenced': True,
        'run_success': False,        # crashed during the optimization run
        'crashes': True,
        # crash verdict present → AnalysisResult appended as the LAST result
        'crash_analysis': {'true_bug': False, 'insight': 'SEGV on random input',
                           'stacktrace': 'cmsDoTransform'},
    }


def test_crash_path_analysisresult_carries_compile_status():
    history = StateAdapter.state_to_result_history(_state_with_crash(True))
    last = history[-1]
    # A crash verdict exists → the last result is the AnalysisResult.
    assert isinstance(last, AnalysisResult), f"expected AnalysisResult, got {type(last).__name__}"
    # THE FIX: a compiled-but-crashed driver must report compiles=True so the merge
    # keeps it as a candidate (preflight then vets the crash), not silently drop it.
    assert getattr(last, 'compiles', False) is True


def test_crash_path_uncompiled_stays_false():
    history = StateAdapter.state_to_result_history(_state_with_crash(False))
    last = history[-1]
    assert isinstance(last, AnalysisResult)
    assert getattr(last, 'compiles', False) is False
