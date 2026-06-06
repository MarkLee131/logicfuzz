"""Role-precision: SVF read-only access vetoes a wrong OUTPUT arg role.

lcms cmsAppendNamedColor's PCS[]/Colorant[] (INPUT arrays the API READS) were
labelled OUTPUT by the LLM, producing a wrong "fresh local, do not pre-fill"
hole intent. The SVF read/write signal (_svf_writes) must demote that OUTPUT.
"""
from liberator_adapter.analysis.api_semantic_model import _reconcile_args, ArgRole


class _IR:
    def __init__(self, roles):
        self.arg_roles = roles


def _roles(api, ir, llm):
    out_args, _log = _reconcile_args(api, ir, None, llm)
    return {a.index: a.role for a in out_args}


def test_svf_readonly_vetoes_llm_output():
    api = {"arguments": [
        {"type": "List *", "_svf_writes": None},
        {"type": "uint16_t *", "_svf_writes": False},  # SVF: reads only
    ]}
    ir = _IR({0: ArgRole.HANDLE_IN, 1: ArgRole.HANDLE_IN})
    roles = _roles(api, ir, {1: ArgRole.OUTPUT})       # LLM wrongly says OUTPUT
    assert roles[1] is not ArgRole.OUTPUT              # vetoed
    assert roles[1] is ArgRole.HANDLE_IN               # fell back to IR pattern


def test_svf_write_keeps_output():
    api = {"arguments": [{"type": "int *", "_svf_writes": True}]}  # SVF: written
    roles = _roles(api, _IR({0: ArgRole.UNKNOWN}), {0: ArgRole.OUTPUT})
    assert roles[0] is ArgRole.OUTPUT                  # genuine out-pointer kept


def test_no_svf_data_keeps_output():
    api = {"arguments": [{"type": "int *"}]}           # _svf_writes absent (None)
    roles = _roles(api, _IR({0: ArgRole.UNKNOWN}), {0: ArgRole.OUTPUT})
    assert roles[0] is ArgRole.OUTPUT                  # no SVF data -> untouched


def test_ir_output_fallback_demoted_to_unknown():
    # If even the IR fallback would be OUTPUT, demote to UNKNOWN (don't bounce).
    api = {"arguments": [{"type": "int *", "_svf_writes": False}]}
    roles = _roles(api, _IR({0: ArgRole.OUTPUT}), {0: ArgRole.OUTPUT})
    assert roles[0] is ArgRole.UNKNOWN
