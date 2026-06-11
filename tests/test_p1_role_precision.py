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


# --- Phase 1.5: symmetric SVF promotion (mirror of the veto) ---

def test_svf_write_promotes_config_pointer_to_output():
    # A non-const POINTER CONFIG that SVF proved is WRITTEN is an under-labelled
    # OUTPUT (caller-alloc / output-array) → promote, mirroring the veto.
    api = {"arguments": [{"type": "cmsCIEXYZ *", "_svf_writes": True}]}
    roles = _roles(api, _IR({0: ArgRole.CONFIG}), {0: ArgRole.CONFIG})
    assert roles[0] is ArgRole.OUTPUT


def test_svf_write_does_not_promote_handle_in():
    # HANDLE_IN is commonly in-out; an SVF write must NOT flip it to OUTPUT
    # (the gate that keeps a mutated handle from being misclassified).
    api = {"arguments": [{"type": "cmsHPROFILE *", "_svf_writes": True}]}
    roles = _roles(api, _IR({0: ArgRole.HANDLE_IN}), {0: ArgRole.HANDLE_IN})
    assert roles[0] is ArgRole.HANDLE_IN


def test_svf_write_does_not_promote_const_pointer():
    # A const pointer is read-only by contract → never promoted even if SVF
    # (spuriously) reports a write.
    api = {"arguments": [{"type": "const int *", "_svf_writes": True}]}
    roles = _roles(api, _IR({0: ArgRole.CONFIG}), {0: ArgRole.CONFIG})
    assert roles[0] is ArgRole.CONFIG
