"""Value-flow-augmented Prefix Tree Acceptor.

Folds a set of ``StaticTrace``s into a tree where each node represents the
abstract handle-typestate vector reached after replaying that trace prefix.
Edges are labeled with ``(api_name, binding_pattern)``; the binding pattern
records, for each handle slot of the call, whether it was satisfied by
DEF-ing this call (out-pointer / return) or by referring to a previously
DEF'd handle.

The PTA is the input to the EDSM merging engine in ``edsm.py`` and the
LLM-equivalence oracle in ``llm_oracle.py``. Reference: Higuera 2010 §5
(Prefix Tree Acceptor); Lang/Pearlmutter/Price 1998 (EDSM).

Design notes
------------
* State value: ``frozenset[(handle_type, lifecycle_state)]``. We freeze so
  states are hashable and structurally compared. ``ResourceLifecycleState``
  is reused from ``usedef.py`` (UNINIT / INIT / DESTROYED).
* The walk is deterministic and additive — each trace touches exactly one
  path; new edges or DEF'd handles extend the tree.
* We attach a ``WitnessSet`` to every node tracking which traces reached
  it; EDSM uses these as evidence weights.
* Edges keyed by ``(api_name, binding_pattern_hash)`` so two distinct
  call-shapes for the same API produce distinct edges.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from liberator_adapter.analysis.static_trace import CallSite, StaticTrace
from liberator_adapter.analysis.usedef import (
    APIEffect,
    HandleType,
    ResourceLifecycleState,
    UseDefGraph,
)


# A single (handle_type → lifecycle_state) snapshot.
StateVector = FrozenSet[Tuple[HandleType, ResourceLifecycleState]]


def _state_vector(open_handles: Dict[HandleType, ResourceLifecycleState]) -> StateVector:
    return frozenset(open_handles.items())


# ----------------------------------------------------------------------- edges

# A binding pattern is a tuple of (arg_idx, "DEF") or (arg_idx, "USE")
# entries — DEF when the slot delivers a handle outward (return / out-pointer)
# and USE when it consumes a previously DEF'd handle. The pattern is
# canonicalized (sorted) so equal-shaped calls collide on the same edge key.
BindingPattern = Tuple[Tuple[int, str], ...]


def _binding_pattern(call: CallSite, eff: Optional[APIEffect]) -> BindingPattern:
    """Best-effort tuple summarizing how this call interacts with handle args.

    Out-pointer / return slots are marked DEF; bound USE slots are USE.
    Slots without binding info are omitted so that a USE-without-binding does
    not split equivalent edges.
    """
    parts: List[Tuple[int, str]] = []
    if call.return_var:
        parts.append((-1, "DEF"))  # return channel sentinel
    for arg_idx in sorted(call.arg_bindings.keys()):
        parts.append((arg_idx, "USE"))
    # An out-pointer slot is recorded by ``static_trace.py`` as a DEF in
    # var_to_call rather than in arg_bindings; recover it heuristically by
    # asking the APIEffect which arg slots produce a handle via out-pointer.
    if eff is not None:
        for prod in eff.productions:
            if prod.channel.value == "out_pointer":
                # We don't carry the original arg index in productions; mark
                # an unbound DEF slot so the pattern still distinguishes.
                parts.append((-2, "DEF"))
                break
    return tuple(sorted(set(parts)))


# ----------------------------------------------------------------------- nodes

@dataclass
class PTANode:
    """One state in the prefix tree.

    ``state`` is the structured handle-typestate vector reached at this node.
    ``children`` maps an outgoing edge key (api_name, binding_pattern) to
    the child node id. ``witness_traces`` records which trace ids passed
    through this node — EDSM uses the cardinality as evidence weight.
    """
    node_id: int
    state: StateVector
    children: Dict[Tuple[str, BindingPattern], int] = field(default_factory=dict)
    witness_traces: Set[int] = field(default_factory=set)
    incoming_edge_label: Optional[Tuple[str, BindingPattern]] = None
    parent_id: Optional[int] = None

    def to_dict(self):
        return {
            "node_id": self.node_id,
            "state": [
                {"handle": h, "state": s.value}
                for h, s in sorted(self.state)
            ],
            "children": {
                f"{api}|{bp}": child_id
                for (api, bp), child_id in self.children.items()
            },
            "witness_count": len(self.witness_traces),
            "incoming_edge": (
                f"{self.incoming_edge_label[0]}|{self.incoming_edge_label[1]}"
                if self.incoming_edge_label else None
            ),
            "parent_id": self.parent_id,
        }


# ----------------------------------------------------------------------- PTA

class PrefixTreeAcceptor:
    """The PTA itself. Build by feeding ``add_trace`` for each trace, then
    pass to ``edsm.merge`` to obtain a generalized automaton.
    """

    def __init__(self, graph: UseDefGraph):
        self.graph = graph
        # Initial state = all handles uninitialized. We don't bother to
        # enumerate the universe of handle types — UNINIT is the default
        # whenever a handle isn't in the dict.
        self.root = PTANode(node_id=0, state=frozenset())
        self.nodes: Dict[int, PTANode] = {0: self.root}
        self._next_id = 1

    def add_trace(self, trace_id: int, trace: StaticTrace) -> None:
        """Replay one trace, extending the tree where necessary."""
        cur = self.root
        cur.witness_traces.add(trace_id)
        # Track open handles along this single trace replay; a list-of-counts
        # per handle type is overkill — typestate alone (UNINIT/INIT/DESTROYED)
        # collapses any number of opens into INIT.
        open_handles: Dict[HandleType, ResourceLifecycleState] = dict(cur.state)
        for call in trace.api_calls:
            eff = self.graph.effect(call.api_name)
            self._apply_effect(open_handles, eff)
            label = (call.api_name, _binding_pattern(call, eff))
            child_id = cur.children.get(label)
            if child_id is None:
                child = PTANode(
                    node_id=self._next_id,
                    state=_state_vector(open_handles),
                    incoming_edge_label=label,
                    parent_id=cur.node_id,
                )
                self._next_id += 1
                self.nodes[child.node_id] = child
                cur.children[label] = child.node_id
            else:
                child = self.nodes[child_id]
            child.witness_traces.add(trace_id)
            cur = child

    @staticmethod
    def _apply_effect(open_handles: Dict[HandleType, ResourceLifecycleState],
                      eff: Optional[APIEffect]) -> None:
        if eff is None:
            return
        for h in eff.kill:
            open_handles[h] = ResourceLifecycleState.DESTROYED
        for h in eff.def_:
            # DEF resets to INIT regardless of prior state; pure typestate
            # (no count) is enough at this granularity.
            open_handles[h] = ResourceLifecycleState.INITIALIZED

    # ---- queries ----
    def size(self) -> int:
        return len(self.nodes)

    def edges(self) -> int:
        return sum(len(n.children) for n in self.nodes.values())

    def to_dict(self):
        return {
            "node_count": self.size(),
            "edge_count": self.edges(),
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
        }

    def reachable_state_summary(self) -> Dict[str, int]:
        """Histogram of distinct state vectors. Useful for sanity printing."""
        from collections import Counter
        c = Counter(n.state for n in self.nodes.values())
        return {f"{len(s)} handles": v for s, v in c.items()}


def build_pta(traces: List[StaticTrace], graph: UseDefGraph) -> PrefixTreeAcceptor:
    pta = PrefixTreeAcceptor(graph)
    for i, t in enumerate(traces):
        pta.add_trace(i, t)
    return pta
