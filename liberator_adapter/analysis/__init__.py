"""Use-def + typestate analysis primitives shared across L1/L2/L3 filters.

The progressive filter pipeline historically had three independent
implementations of "look at API signatures, infer some relation, validate a
sequence against it" — one per file in ``constraints/``. This module
consolidates the underlying *data flow* model so that each Lx filter becomes
a thin typestate query rather than a hand-written matcher.

Theory anchor:
- ``APIEffect`` → reaching-definition / mod-ref summary per API
  (Aho/Sethi/Ullman, *Compilers* Ch.9).
- ``UseDefGraph`` → library-wide def-use chain.
- ``Typestate`` → resource state automaton (Strom & Yemini, IEEE TSE 1986).
"""
from liberator_adapter.analysis.usedef import (
    APIEffect,
    HandleType,
    UseDefGraph,
    Typestate,
    ResourceLifecycleState,
    ViolationKind,
    ViolationRecord,
    extract_api_effects,
)
from liberator_adapter.analysis.static_trace import (
    CallSite,
    StaticTrace,
    ProjectTraceReport,
    extract_project_traces,
)
from liberator_adapter.analysis.pta import (
    PrefixTreeAcceptor,
    PTANode,
    build_pta,
)
from liberator_adapter.analysis.edsm import EDSMResult, merge as edsm_merge
from liberator_adapter.analysis.llm_oracle import LLMEquivalenceOracle
from liberator_adapter.analysis.project_automaton import (
    AutomatonArtifact,
    learn_project_automaton,
)
from liberator_adapter.analysis.api_semantic_model import (
    APIRole,
    ArgRole,
    EvidenceSource,
    Evidence,
    ArgSemantics,
    APISemantics,
    APISemanticModel,
    reconcile,
)
from liberator_adapter.analysis.sequence_constructor import (
    ConstructionResult,
    construct_sequences,
)
from liberator_adapter.analysis.hole_semantics import (
    annotate_skeletons,
    value_intents_for_sequence,
    render_value_intents,
    render_callspec,
)
from liberator_adapter.analysis.coverage_gap import (
    compute_gap_apis,
    locate_baseline_textcov,
    parse_textcov_covered,
)

__all__ = [
    "APIEffect",
    "HandleType",
    "UseDefGraph",
    "Typestate",
    "ResourceLifecycleState",
    "ViolationKind",
    "ViolationRecord",
    "extract_api_effects",
    "CallSite",
    "StaticTrace",
    "ProjectTraceReport",
    "extract_project_traces",
    "PrefixTreeAcceptor",
    "PTANode",
    "build_pta",
    "EDSMResult",
    "edsm_merge",
    "LLMEquivalenceOracle",
    "AutomatonArtifact",
    "learn_project_automaton",
    "APIRole",
    "ArgRole",
    "EvidenceSource",
    "Evidence",
    "ArgSemantics",
    "APISemantics",
    "APISemanticModel",
    "reconcile",
    "ConstructionResult",
    "construct_sequences",
    "annotate_skeletons",
    "value_intents_for_sequence",
    "render_value_intents",
    "render_callspec",
    "compute_gap_apis",
    "locate_baseline_textcov",
    "parse_textcov_covered",
]
