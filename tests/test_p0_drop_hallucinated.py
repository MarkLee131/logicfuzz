"""Tests for _drop_hallucinated_calls (L5a — auto-drop pre-build).

Import via importlib.util so the circular-import chain in
src/agents/__init__.py → src/workflow/… → src/agents is never triggered.
"""
import sys, pathlib, importlib.util

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Load prototyper.py directly, skipping the package __init__.py
_spec = importlib.util.spec_from_file_location(
    "src.agents.prototyper",
    ROOT / "src" / "agents" / "prototyper.py",
)
_mod = importlib.util.module_from_spec(_spec)
# Stub out heavy top-level imports that would pull in the full chain
import types as _types
for _name in (
    "langchain_core.tools",
    "langchain_core.tools.base",
    "src.workflow.state",
    "src.agents.base",
    "src.agents.tool_calling_mixin",
    "src.agents.utils",
    "src.utils.prompt_loader",
    "data_prep.api_classifier",
    "logger",
):
    if _name not in sys.modules:
        sys.modules[_name] = _types.ModuleType(_name)

# Provide minimal stubs that the module-level code actually uses
sys.modules.setdefault("langchain_core", _types.ModuleType("langchain_core"))
_lc_tools = sys.modules.setdefault("langchain_core.tools", _types.ModuleType("langchain_core.tools"))
if not hasattr(_lc_tools, "BaseTool"):
    _lc_tools.BaseTool = object  # type: ignore[attr-defined]

_base_mod = sys.modules["src.agents.base"]
class _LangGraphAgentStub:
    pass

class _ToolCallingMixinStub:
    pass

if not hasattr(_base_mod, "LangGraphAgent"):
    _base_mod.LangGraphAgent = _LangGraphAgentStub  # type: ignore[attr-defined]

_state_mod = sys.modules["src.workflow.state"]
if not hasattr(_state_mod, "FuzzingWorkflowState"):
    _state_mod.FuzzingWorkflowState = object  # type: ignore[attr-defined]

_mixin_mod = sys.modules["src.agents.tool_calling_mixin"]
if not hasattr(_mixin_mod, "ToolCallingMixin"):
    _mixin_mod.ToolCallingMixin = _ToolCallingMixinStub  # type: ignore[attr-defined]

_utils_mod = sys.modules["src.agents.utils"]
if not hasattr(_utils_mod, "parse_tag"):
    _utils_mod.parse_tag = lambda *a, **kw: None  # type: ignore[attr-defined]

_pl_mod = sys.modules["src.utils.prompt_loader"]
if not hasattr(_pl_mod, "get_prompt_manager"):
    _pl_mod.get_prompt_manager = lambda *a, **kw: None  # type: ignore[attr-defined]

_dc_mod = sys.modules["data_prep.api_classifier"]
if not hasattr(_dc_mod, "classify_project_apis"):
    _dc_mod.classify_project_apis = lambda *a, **kw: None  # type: ignore[attr-defined]

_logger_mod = sys.modules["logger"]
_logger_mod.warning = lambda *a, **kw: None  # type: ignore[attr-defined]
_logger_mod.info = lambda *a, **kw: None  # type: ignore[attr-defined]
_logger_mod.error = lambda *a, **kw: None  # type: ignore[attr-defined]

_spec.loader.exec_module(_mod)  # type: ignore[union-attr]
_drop_hallucinated_calls = _mod._drop_hallucinated_calls


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_drops_offending_statement_no_substitute():
    code = "a();\n  cmsBogusApi(x, y);\n  b();\n"
    out = _drop_hallucinated_calls(code, {"cmsBogusApi"})
    assert "cmsBogusApi" not in out
    assert "a();" in out and "b();" in out
    assert "cmsBogus" not in out


def test_empty_names_returns_original():
    code = "a();\n  cmsRealApi(x);\n  b();\n"
    out = _drop_hallucinated_calls(code, set())
    assert out == code


def test_no_call_syntax_on_line_is_kept():
    """A line that merely mentions the name (no '(') must be preserved."""
    code = "// cmsBogusApi is not called here\n  a();\n"
    out = _drop_hallucinated_calls(code, {"cmsBogusApi"})
    assert "cmsBogusApi" in out  # comment line kept (no call parens)
    assert "a();" in out


def test_multiple_names_drops_all():
    code = "  cmsHallA(x);\n  cmsHallB(y);\n  cmsReal(z);\n"
    out = _drop_hallucinated_calls(code, {"cmsHallA", "cmsHallB"})
    assert "cmsHallA" not in out
    assert "cmsHallB" not in out
    assert "cmsReal(z);" in out


def test_word_boundary_no_false_positive():
    """'cmsBogusApiExtra' must NOT be dropped when only 'cmsBogusApi' is hallucinated."""
    code = "  cmsBogusApiExtra(x);\n  cmsBogusApi(y);\n"
    out = _drop_hallucinated_calls(code, {"cmsBogusApi"})
    # cmsBogusApiExtra does NOT match \bcmsBogusApi\s*\(
    assert "cmsBogusApiExtra" in out
    assert "cmsBogusApi(y);" not in out


def test_trailing_newline_preserved():
    """splitlines() drops the terminal newline — the join must restore it."""
    code = "a();\nbogus(x);\n"
    out = _drop_hallucinated_calls(code, {"bogus"})
    assert out == "a();\n", repr(out)


def test_trailing_newline_preserved_no_drop():
    """Trailing newline also preserved when nothing is dropped."""
    code = "a();\nb();\n"
    out = _drop_hallucinated_calls(code, {"bogus"})
    assert out == code


# ---------------------------------------------------------------------------
# Integration: _validate_api_usage return type
# ---------------------------------------------------------------------------

def test_validate_api_usage_returns_2_tuple():
    """_validate_api_usage must return (str, str) — guard against regressions
    from the earlier single-str return type."""
    import types as _t

    # Build a minimal stub instance of LangGraphPrototyper without going
    # through __init__ (which requires argparse.Namespace + live LLM).
    LangGraphPrototyper = _mod.LangGraphPrototyper

    obj = object.__new__(LangGraphPrototyper)
    # Attributes referenced by _validate_api_usage / _scan_hole_hallucinations
    obj.trial = 0

    # Stub out the logger that the method calls via module-level 'logger'
    import types
    logger_stub = types.SimpleNamespace(
        warning=lambda *a, **kw: None,
        info=lambda *a, **kw: None,
        error=lambda *a, **kw: None,
    )
    _mod.logger = logger_stub  # type: ignore[attr-defined]

    code = "int main() { return 0; }\n"
    result = obj._validate_api_usage(code, "testproject", known_apis=[])

    # Must be a 2-tuple of (str, str)
    assert isinstance(result, tuple), f"expected tuple, got {type(result)}"
    assert len(result) == 2, f"expected 2-tuple, got length {len(result)}"
    warnings, rewritten = result
    assert isinstance(warnings, str), f"warnings must be str, got {type(warnings)}"
    assert isinstance(rewritten, str), f"rewritten must be str, got {type(rewritten)}"
