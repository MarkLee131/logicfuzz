"""LogicFuzz knowledge layer.

Two-stage comprehender:
- comprehender-A (per-API usage): runs on the unique APIs that appear in
  top-K sequences after L0–L3 filtering. Layered fallback: deterministic facts
  from ConditionManager → batched LLM as last resort.
- comprehender-B (sequence semantics): runs on each top-K candidate sequence,
  judges semantic validity beyond what L0–L3 can prove, optionally proposes a
  repair, and emits invariants for the prototyper.

Both stages share an on-disk cache keyed by (project, content_hash) so that
re-runs and downstream agents pay zero LLM cost.
"""

from src.knowledge.cache import KnowledgeCache
from src.knowledge.comprehender import (
    LibraryComprehension,
    SequenceSemantics,
    Comprehender,
)

__all__ = [
    "KnowledgeCache",
    "LibraryComprehension",
    "SequenceSemantics",
    "Comprehender",
]
