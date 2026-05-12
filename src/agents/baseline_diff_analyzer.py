"""
LangGraphBaselineDiffAnalyzer agent (§10B v2 of the knowledge layer
design proposal, 2026-05-12).

Triggered when ``baseline_regression_alert`` fires: our generated
driver compiled and ran, but ``line_coverage_diff`` (the NEW lines
beyond the existing OSS-Fuzz baseline driver) is < 0.5%. This is a
strong signal that we are "moving around inside what the baseline
already covers" rather than reaching new code. v1 emits the alert;
v2 (this agent) compares the two drivers and instructs the
Prototyper what context to recover.

Design choices:
  - No tools. Pure context-in, structured-out. We already pre-fetch
    the baseline source and the current driver source. Adding the
    bash tool would invite "let me grep the repo" detours that don't
    pay off for a single-turn analysis.
  - Stateless one-shot LLM call via ``LangGraphAgent.call_llm_stateless``.
  - Output goes into ``state['baseline_diff_analysis']`` for the
    Prototyper to consume on its next pass. The Prototyper renders
    it into a ``<baseline_regression_recovery>`` block.

The instruction set is deliberately narrow: identify CONCRETE gaps
between our driver and the baseline along four axes
  - missing_apis: APIs the baseline calls that ours does not
  - missing_patterns: structural patterns (input encoding, multi-mode
    pathways, init/destroy lifecycle) ours dropped
  - input_encoding_gaps: how the baseline ingests/derives input vs ours
  - suggested_constraints: rules the Prototyper should follow on
    re-generate (one line each, imperative)
"""
import argparse
import re
from typing import Any, Dict, List

import logger
from langchain_core.tools import BaseTool

from src.workflow.state import FuzzingWorkflowState
from src.agents.base import LangGraphAgent


_SYSTEM_MESSAGE = """\
You are a senior fuzzing engineer reviewing two drivers for the same
library:
  - DRIVER_OURS: produced by the current pipeline. It compiled and
    ran, but contributed almost no NEW coverage over the baseline.
  - DRIVER_BASELINE: the hand-written OSS-Fuzz fuzz driver shipped
    by the project maintainers (gold standard).

Your job is to identify the CONCRETE context our driver dropped from
the baseline. Be specific, not generic. The output is consumed
verbatim by a re-prototyping pass — vague advice ("use more APIs")
wastes a re-generation budget.

Critical: the baseline is NOT always right. If a pattern in the
baseline is obviously narrow (e.g. fixed mode never varied), say
so. Forcing copy of an irrelevant pattern is worse than ignoring
the baseline.

Output exactly these XML-tagged sections, in order:

<missing_apis>
One line per API present in the baseline but absent from ours.
Format: `<api_name> — <one-line reason it matters for coverage>`
List 0-8 APIs; if none, write `none`.
</missing_apis>

<missing_patterns>
One line per structural pattern present in the baseline but absent
from ours. Examples: byte-toggle input encoding, multi-mode print
(formatted/unformatted/buffered), init→use→destroy lifecycle,
callback registration, repeated parse/encode round-trip.
List 0-6 patterns; if none, write `none`.
</missing_patterns>

<input_encoding_gaps>
2-4 sentence comparison of how the baseline derives test input from
the LibFuzzer `data, size` buffer vs how ours does. If ours just
passes data straight through and the baseline structures it (e.g.
splits into mode-byte + payload, generates a JSON tree from bytes),
SAY SO. If both are equivalent, write `equivalent`.
</input_encoding_gaps>

<suggested_constraints>
3-8 imperative one-liners the re-prototyper MUST follow. Each line
must be ACTIONABLE and SPECIFIC to this library, not generic
fuzz-driver advice. Bad: "call more APIs". Good: "Derive a
print-mode index from data[0] % 4 and dispatch to cJSON_Print,
cJSON_PrintUnformatted, cJSON_PrintBuffered, cJSON_PrintPreallocated".
</suggested_constraints>

<verdict>
One word from: recover | baseline_too_narrow | inconclusive.
  - `recover`: the baseline carries useful structure ours dropped;
    re-prototype with the suggestions above.
  - `baseline_too_narrow`: the baseline itself looks shallow and
    copying it won't help; the regression is real but recovery
    will not come from this diff.
  - `inconclusive`: the two drivers diverge but the gap is too
    ambiguous to recommend a concrete re-prototype direction.
</verdict>
"""


_VERDICT_VALUES = ("recover", "baseline_too_narrow", "inconclusive")
_MAX_DRIVER_CHARS = 6000   # ~1500 tokens per driver, well within budget


def _truncate(text: str, limit: int = _MAX_DRIVER_CHARS) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[... truncated {len(text) - limit} chars]"


class LangGraphBaselineDiffAnalyzer(LangGraphAgent):
    """Compare DRIVER_OURS vs DRIVER_BASELINE and produce repair hints."""

    def __init__(self, model_name: str, trial: int, args: argparse.Namespace):
        super().__init__(
            name="baseline_diff_analyzer",
            model_name=model_name,
            trial=trial,
            args=args,
            system_message=_SYSTEM_MESSAGE,
        )

    def get_tools(self) -> List[BaseTool]:  # pragma: no cover - unused
        return []

    def execute(self, state: FuzzingWorkflowState) -> Dict[str, Any]:
        context = state.get("context", {}) or {}
        knowledge = context.get("existing_driver_knowledge", {}) or {}
        driver_sources = knowledge.get("driver_sources", []) or []
        baseline_src = ""
        baseline_path = ""
        if driver_sources:
            first = driver_sources[0]
            baseline_src = first.get("source", "") or ""
            baseline_path = first.get("path", "") or ""

        ours = state.get("fuzz_target_source", "") or ""
        if not ours or not baseline_src:
            logger.warning(
                "BaselineDiffAnalyzer skipped: missing %s",
                "ours" if not ours else "baseline",
                trial=self.trial,
            )
            self._langgraph_logger.flush_agent_logs(self.name)
            return {
                "baseline_diff_analysis": {
                    "status": "skipped",
                    "reason": "missing_inputs",
                },
            }

        alert = state.get("baseline_regression_alert", {}) or {}
        project = state.get("benchmark", {}).get("project", "unknown")

        target_apis: List[str] = []
        for api in context.get("project_apis", []) or []:
            if isinstance(api, dict):
                name = api.get("name") or api.get("function_name")
            else:
                name = getattr(api, "name", None) or getattr(api, "function_name", None)
            if name:
                target_apis.append(str(name))

        prompt = (
            f"Project: {project}\n"
            f"Baseline driver path: {baseline_path or 'unknown'}\n"
            f"Regression signal: line_coverage_diff="
            f"{alert.get('line_diff', 0):.4f} "
            f"(threshold {alert.get('threshold', 0):.4f}); "
            f"coverage_percent={alert.get('coverage_percent', 0):.4f}.\n"
            f"Project APIs (truncated, first 40): "
            f"{', '.join(target_apis[:40]) or 'unavailable'}\n"
            "\n"
            "<driver_ours>\n"
            f"{_truncate(ours)}\n"
            "</driver_ours>\n"
            "\n"
            "<driver_baseline>\n"
            f"{_truncate(baseline_src)}\n"
            "</driver_baseline>\n"
            "\n"
            "Produce the five tagged sections from the system message."
        )

        response = self.call_llm_stateless(
            prompt=prompt, state=state, log_prefix="BASELINE_DIFF")
        parsed = self._parse_response(response)
        parsed["raw_response"] = response

        logger.info(
            "BaselineDiffAnalyzer verdict=%s | missing_apis=%d | "
            "missing_patterns=%d | constraints=%d",
            parsed.get("verdict", "unknown"),
            len(parsed.get("missing_apis", [])),
            len(parsed.get("missing_patterns", [])),
            len(parsed.get("suggested_constraints", [])),
            trial=self.trial,
        )

        self._langgraph_logger.flush_agent_logs(self.name)
        return {"baseline_diff_analysis": parsed}

    @staticmethod
    def _extract_block(text: str, tag: str) -> str:
        match = re.search(
            rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL | re.IGNORECASE)
        if not match:
            return ""
        return match.group(1).strip()

    @classmethod
    def _parse_response(cls, response: str) -> Dict[str, Any]:
        def _split_lines(block: str) -> List[str]:
            out: List[str] = []
            for raw in block.splitlines():
                line = raw.strip().lstrip("-•*").strip()
                if not line:
                    continue
                if line.lower() == "none":
                    return []
                out.append(line)
            return out

        missing_apis_block = cls._extract_block(response, "missing_apis")
        missing_patterns_block = cls._extract_block(response, "missing_patterns")
        constraints_block = cls._extract_block(response, "suggested_constraints")
        input_encoding = cls._extract_block(response, "input_encoding_gaps")
        verdict_raw = cls._extract_block(response, "verdict").lower().strip()
        verdict = verdict_raw if verdict_raw in _VERDICT_VALUES else "inconclusive"

        return {
            "status": "ok",
            "missing_apis": _split_lines(missing_apis_block),
            "missing_patterns": _split_lines(missing_patterns_block),
            "input_encoding_gaps": input_encoding,
            "suggested_constraints": _split_lines(constraints_block),
            "verdict": verdict,
        }
