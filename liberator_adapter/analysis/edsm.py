"""Evidence-Driven State Merging on a value-flow PTA.

Reference: Lang, Pearlmutter, Price (1998), *Results of the Abbadingo One DFA
learning competition and a new evidence-driven state merging algorithm*. We
adapt the classical algorithm in three ways:

1. **State compatibility is structural, not just suffix-language**: two PTA
   states can only merge if their typestate vectors are identical. Equal
   typestate is necessary but not sufficient — same suffix language is the
   sufficient layer on top.
2. **Evidence comes from witness counts**, not random walks. Each PTA node
   carries the set of trace ids that reached it; merging two nodes
   accumulates evidence proportional to their joint witness mass.
3. **Uncertain merges are deferred to the LLM oracle** (``llm_oracle.py``)
   instead of being decided heuristically. The oracle's verdict is treated
   as one extra evidence signal.

The merge operates on a quotient view (a union-find over PTA node ids) so
the underlying PTA is never mutated and the EDSM run is reproducible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from liberator_adapter.analysis.pta import (
    BindingPattern,
    PrefixTreeAcceptor,
    PTANode,
)


# Oracle verdict on whether two abstract states represent the same library
# state. ``None`` means "uncertain — defer". A bound oracle that always
# returns ``None`` reduces EDSM to evidence-only mode.
OracleVerdict = Optional[bool]
OracleFn = Callable[[PTANode, PTANode, "EDSMContext"], OracleVerdict]


# ----------------------------------------------------------------------- UnionFind

class _UnionFind:
    __slots__ = ("parent", "rank")

    def __init__(self, ids: Iterable[int]):
        self.parent: Dict[int, int] = {i: i for i in ids}
        self.rank: Dict[int, int] = {i: 0 for i in ids}

    def find(self, x: int) -> int:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


# ----------------------------------------------------------------------- context

@dataclass
class EDSMContext:
    """Shared state passed to oracle calls and merge scoring."""
    pta: PrefixTreeAcceptor
    uf: _UnionFind
    library_purpose: str = ""
    library_name: str = ""

    def witnesses_of(self, node_id: int) -> Set[int]:
        """All trace ids that reach the *equivalence class* containing this node."""
        rep = self.uf.find(node_id)
        out: Set[int] = set()
        for nid, n in self.pta.nodes.items():
            if self.uf.find(nid) == rep:
                out.update(n.witness_traces)
        return out

    def out_edges_of(self,
                     node_id: int,
                     ) -> Dict[Tuple[str, BindingPattern], int]:
        """Outgoing edges of an equivalence class — union of constituents."""
        rep = self.uf.find(node_id)
        out: Dict[Tuple[str, BindingPattern], int] = {}
        for nid, n in self.pta.nodes.items():
            if self.uf.find(nid) == rep:
                for label, child in n.children.items():
                    out[label] = self.uf.find(child)
        return out


# ----------------------------------------------------------------------- scoring

@dataclass
class MergeProposal:
    """A candidate merge of two equivalence classes."""
    a_rep: int
    b_rep: int
    score: float        # higher = stronger signal to merge
    rationale: List[str] = field(default_factory=list)


def _state_compatibility(a: PTANode, b: PTANode) -> bool:
    """Necessary precondition: identical handle-typestate vector."""
    return a.state == b.state


def _suffix_overlap(ctx: EDSMContext, a: int, b: int, depth: int = 2) -> int:
    """Count of common outgoing edge labels up to ``depth`` levels.

    Higher overlap → stronger evidence the two classes accept the same
    continuations. Conservative: we only look at the *labels*, not whether
    the destinations have already been merged.
    """
    if depth <= 0:
        return 0
    a_edges = ctx.out_edges_of(a)
    b_edges = ctx.out_edges_of(b)
    common_labels = set(a_edges) & set(b_edges)
    score = len(common_labels)
    if depth > 1:
        for lbl in common_labels:
            score += _suffix_overlap(ctx, a_edges[lbl], b_edges[lbl], depth - 1)
    return score


def _score_merge(ctx: EDSMContext,
                 a_node: PTANode,
                 b_node: PTANode,
                 oracle_verdict: OracleVerdict) -> MergeProposal:
    rationale: List[str] = []
    score = 0.0
    if a_node.state == b_node.state:
        score += 1.0
        rationale.append("typestate_match")
    overlap = _suffix_overlap(ctx, a_node.node_id, b_node.node_id, depth=2)
    if overlap > 0:
        score += min(overlap, 5)  # cap to avoid runaway
        rationale.append(f"suffix_overlap={overlap}")
    a_w = len(a_node.witness_traces)
    b_w = len(b_node.witness_traces)
    score += min(a_w, b_w) ** 0.5  # diminishing returns on witness mass
    rationale.append(f"witnesses={a_w}+{b_w}")
    if oracle_verdict is True:
        score += 5.0
        rationale.append("oracle_yes")
    elif oracle_verdict is False:
        score = -1.0  # veto
        rationale.append("oracle_no_VETO")
    return MergeProposal(
        a_rep=a_node.node_id, b_rep=b_node.node_id,
        score=score, rationale=rationale,
    )


# ----------------------------------------------------------------------- merger

@dataclass
class EDSMResult:
    pta: PrefixTreeAcceptor
    uf: _UnionFind
    n_input_states: int
    n_output_states: int
    n_proposals_evaluated: int
    n_merges_applied: int
    n_oracle_yes: int
    n_oracle_no: int
    n_oracle_uncertain: int
    library_name: str = ""

    def equivalence_classes(self) -> Dict[int, List[int]]:
        out: Dict[int, List[int]] = {}
        for nid in self.pta.nodes:
            rep = self.uf.find(nid)
            out.setdefault(rep, []).append(nid)
        return out

    def to_dict(self) -> Dict:
        classes = self.equivalence_classes()
        return {
            "library_name": self.library_name,
            "n_input_states": self.n_input_states,
            "n_output_states": self.n_output_states,
            "n_proposals_evaluated": self.n_proposals_evaluated,
            "n_merges_applied": self.n_merges_applied,
            "n_oracle_yes": self.n_oracle_yes,
            "n_oracle_no": self.n_oracle_no,
            "n_oracle_uncertain": self.n_oracle_uncertain,
            "compression_ratio": (
                round(self.n_output_states / self.n_input_states, 3)
                if self.n_input_states else 0.0
            ),
            "class_sizes_top10": sorted(
                (len(v) for v in classes.values()), reverse=True
            )[:10],
        }


def merge(pta: PrefixTreeAcceptor,
          oracle: Optional[OracleFn] = None,
          library_name: str = "",
          library_purpose: str = "",
          min_score_to_merge: float = 1.5,
          max_merges: Optional[int] = None) -> EDSMResult:
    """Run EDSM on the given PTA; return the union-find quotient.

    Strategy: for every pair of nodes with identical state vector, call the
    oracle (if any) and score the merge. Apply merges in descending score
    order, but only when the score clears ``min_score_to_merge`` and the
    oracle hasn't vetoed.

    The state-vector partition is essential: without it we'd have N²/2
    candidate pairs (intractable for sqlite3's ~1000-node PTA). With it we
    only consider pairs within the same typestate bucket, which empirically
    gives ~30 buckets of ~30 nodes each on sqlite3 — quadratic only inside
    each bucket.
    """
    uf = _UnionFind(pta.nodes.keys())
    ctx = EDSMContext(
        pta=pta, uf=uf,
        library_name=library_name, library_purpose=library_purpose,
    )

    # Group nodes by state vector
    by_state: Dict = {}
    for nid, node in pta.nodes.items():
        by_state.setdefault(node.state, []).append(nid)

    proposals: List[MergeProposal] = []
    n_evaluated = 0
    n_yes = n_no = n_uncertain = 0
    for state, nids in by_state.items():
        if len(nids) < 2:
            continue
        # Pairwise within the same state-vector bucket. Order by node_id
        # so seeded from the root down (root has the smallest id).
        nids.sort()
        for i in range(len(nids)):
            for j in range(i + 1, len(nids)):
                a = pta.nodes[nids[i]]
                b = pta.nodes[nids[j]]
                if not _state_compatibility(a, b):
                    continue  # safety, should be true by bucketing
                verdict: OracleVerdict = None
                if oracle is not None:
                    try:
                        verdict = oracle(a, b, ctx)
                    except Exception:
                        verdict = None
                n_evaluated += 1
                if verdict is True:
                    n_yes += 1
                elif verdict is False:
                    n_no += 1
                else:
                    n_uncertain += 1
                proposals.append(_score_merge(ctx, a, b, verdict))

    proposals.sort(key=lambda p: p.score, reverse=True)
    n_applied = 0
    for prop in proposals:
        if max_merges is not None and n_applied >= max_merges:
            break
        if prop.score < min_score_to_merge:
            break
        ra = uf.find(prop.a_rep)
        rb = uf.find(prop.b_rep)
        if ra == rb:
            continue
        uf.union(ra, rb)
        n_applied += 1

    output_classes = {uf.find(nid) for nid in pta.nodes}
    return EDSMResult(
        pta=pta, uf=uf,
        n_input_states=pta.size(),
        n_output_states=len(output_classes),
        n_proposals_evaluated=n_evaluated,
        n_merges_applied=n_applied,
        n_oracle_yes=n_yes,
        n_oracle_no=n_no,
        n_oracle_uncertain=n_uncertain,
        library_name=library_name,
    )
