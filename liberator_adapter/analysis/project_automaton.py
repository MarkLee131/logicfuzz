"""Project-adaptive API protocol automaton — orchestrator.

Glue: trace extraction → PTA construction → EDSM merge (with optional LLM
oracle) → on-disk persistence. The artifact it produces is consumed by L4
ranking (Step 5e2) and the Prototyper.

Persistence layout::

    results/{project}/automaton/
        traces.json          # raw extracted static traces
        pta.json             # full prefix tree (debug/inspection)
        merged.json          # post-EDSM equivalence quotient
        metadata.json        # {n_traces, n_states, oracle_stats, ...}
        oracle_cache.json    # LLM oracle decisions, hash-keyed

``learn_project_automaton`` is the public entry point.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from liberator_adapter.analysis.edsm import EDSMResult, merge
from liberator_adapter.analysis.llm_oracle import LLMEquivalenceOracle
from liberator_adapter.analysis.pta import PrefixTreeAcceptor, build_pta
from liberator_adapter.analysis.static_trace import (
    ProjectTraceReport,
    StaticTrace,
    extract_project_traces,
)
from liberator_adapter.analysis.usedef import (
    Typestate,
    UseDefGraph,
    extend_post_def,
    extract_api_effects,
)

logger = logging.getLogger(__name__)


@dataclass
class AutomatonArtifact:
    """Everything ``learn_project_automaton`` produces."""
    project: str
    n_files_parsed: int
    n_traces: int
    n_pta_states: int
    n_merged_states: int
    n_oracle_calls: int
    handle_binding_hit_rate: float
    output_dir: Path
    pta: PrefixTreeAcceptor
    edsm: EDSMResult
    # Underlying use-def graph the PTA was built on; needed by graft_creator_prefix
    # to recover precise USE/DEF effects per API. Optional for back-compat.
    graph: Optional[UseDefGraph] = None
    project_apis: Optional[List[Dict[str, Any]]] = None

    def acceptance_rate(self) -> float:
        """Fraction of training traces fully accepted by the merged automaton.

        A trace is accepted iff every step's edge label exists in the merged
        equivalence class's outgoing edge set. This is the design-doc P1
        exit criterion's "≥80% acceptance" measure.

        Adjacency dict is cached and invalidated when the PTA size or the
        merged-state count changes (closed-loop's ``update_with_traces``
        bumps both, which is the only legitimate mutation path).
        """
        if not self.pta.nodes or self.n_traces == 0:
            return 0.0
        # Reconstruct per-trace path through the original PTA, then verify
        # that the same label sequence is reachable through the quotient.
        accepted = 0
        # Build (or reuse) the rep → outgoing-label → rep adjacency.
        version_key = (self.pta.size(), self.n_merged_states)
        cached = getattr(self, "_acceptance_adj_cache", None)
        if cached is not None and cached[0] == version_key:
            adj = cached[1]
        else:
            adj = {}
            for nid, node in self.pta.nodes.items():
                rep = self.edsm.uf.find(nid)
                outs = adj.setdefault(rep, {})
                for label, child in node.children.items():
                    outs[label] = self.edsm.uf.find(child)
            # Cache via setattr to avoid dataclass-field requirement.
            object.__setattr__(self, "_acceptance_adj_cache", (version_key, adj))
        # We don't carry trace_id → labels directly; recover by walking
        # children from the root with each trace_id present in witnesses.
        trace_paths: Dict[int, List] = {}
        root_rep = self.edsm.uf.find(0)
        # DFS over witness-tagged children
        def walk(node_id: int, path: List):
            node = self.pta.nodes[node_id]
            for tid in node.witness_traces:
                if tid not in trace_paths or len(path) > len(trace_paths[tid]):
                    trace_paths[tid] = list(path)
            for label, child_id in node.children.items():
                walk(child_id, path + [label])
        walk(0, [])
        for tid, labels in trace_paths.items():
            cur = root_rep
            ok = True
            for lbl in labels:
                outs = adj.get(cur, {})
                nxt = outs.get(lbl)
                if nxt is None:
                    ok = False
                    break
                cur = nxt
            if ok:
                accepted += 1
        return accepted / max(1, len(trace_paths))

    # ---------------- API surface for L4 / Prototyper integration ---------------

    def observed_apis(self) -> Set[str]:
        """Set of every API name appearing on any automaton edge.

        Used by L4 to detect candidate sequences that include APIs the
        automaton never observed, which are the prime candidates for
        creator-prefix grafting.
        """
        seen: Set[str] = set()
        for node in self.pta.nodes.values():
            for (api, _bp), _child in node.children.items():
                seen.add(api)
        return seen

    def sample_accepting_paths(self,
                               n: int = 8,
                               max_depth: int = 8,
                               seed: Optional[int] = 0) -> List[List[str]]:
        """Random walks from root through the merged equivalence quotient.

        Each returned sequence is, by construction, an accepting path of the
        learned automaton (acceptance_score == 1.0). These paths *generalise*
        beyond the raw trace corpus because EDSM merges equivalent states,
        so trace A's prefix can compose with trace B's suffix into a fresh
        accepting path that no individual trace contained.

        Used by L4 to inject guaranteed-correct seed candidates and by the
        Prototyper prompt as protocol templates.

        Algorithm: at each node, uniform-random pick over outgoing API
        labels (collapsing edge keys that share the same api_name). Stop on
        leaf or after ``max_depth`` steps. Deduplicate result.
        """
        import random
        rng = random.Random(seed)
        # Build per-equivalence-class adjacency keyed by api_name.
        adj: Dict[int, Dict[str, int]] = {}
        for nid, node in self.pta.nodes.items():
            rep = self.edsm.uf.find(nid)
            outs = adj.setdefault(rep, {})
            for (api, _bp), child_id in node.children.items():
                outs.setdefault(api, self.edsm.uf.find(child_id))
        root_rep = self.edsm.uf.find(0)
        paths: List[List[str]] = []
        seen_paths: Set[Tuple[str, ...]] = set()
        attempts = 0
        # Try ~3x the requested count to dedupe.
        while len(paths) < n and attempts < n * 6:
            attempts += 1
            cur = root_rep
            walk: List[str] = []
            for _ in range(max_depth):
                outs = adj.get(cur)
                if not outs:
                    break
                api = rng.choice(sorted(outs.keys()))
                walk.append(api)
                cur = outs[api]
            if len(walk) >= 2 and tuple(walk) not in seen_paths:
                seen_paths.add(tuple(walk))
                paths.append(walk)
        return paths

    def graft_creator_prefix(
        self,
        sequence: List[str],
        prefer_filter: Optional[Callable[[str], bool]] = None,
        exclude_filter: Optional[Callable[[str], bool]] = None,
    ) -> Optional[List[str]]:
        """Try to ground an unaccepted candidate by prepending creator(s).

        Walks ``sequence`` in order, tracking which handles have been DEF'd
        upstream. For every step whose USE set has unmet handles, queries
        ``UseDefGraph.roots(h)`` for the top-ranked root producer. Each
        producer is prepended once; multiple unmet handles produce a chain
        of creators (deduped, in discovery order).

        ``prefer_filter``: when supplied, the root-selection step **first**
        tries roots for which ``prefer_filter(name)`` returns ``True``. If
        any such root passes the cycle check, it wins; otherwise it falls
        back to the highest-ranked root irrespective of filter. (The
        APISemanticModel now corrects role mislabels up front, so the L4
        ranker — the remaining caller — rarely needs this override.)

        ``exclude_filter``: roots for which ``exclude_filter(name)`` returns
        ``True`` are removed BEFORE consulting ``prefer_filter``, letting a
        caller retry with a different producer than the top-1 root.

        Returns the grafted sequence on success, ``None`` if no graft could
        be made (no `graph` attribute, no unmet handles, or no producer
        found that isn't already in the sequence).
        """
        if not sequence or self.graph is None:
            return None
        produced: Set[str] = set()
        creators_to_prepend: List[str] = []
        seq_set: Set[str] = set(sequence)
        for step in sequence:
            eff = self.graph.effect(step)
            if eff is None:
                continue
            for h in eff.use:
                if h in produced:
                    continue
                # Unmet USE — try to graft a root producer.
                roots = self.graph.roots(h, top_k=3)
                # Drop roots already in the sequence or chosen creators
                # (would create cycles at the protocol level even if
                # type-feasible).
                roots = [r for r in roots
                         if r not in seq_set and r not in creators_to_prepend]
                # Drop roots the caller asked to exclude (e.g. already tried).
                if exclude_filter is not None:
                    roots = [r for r in roots if not exclude_filter(r)]
                if not roots:
                    continue
                # Idiom-aware preference: try preferred roots first; only fall
                # back to the highest-ranked if none of the top-K are
                # idiom-blessed. Makes graft robust against IR mod/ref
                # false-positive CREATE labels.
                chosen: Optional[str] = None
                if prefer_filter is not None:
                    preferred = [r for r in roots if prefer_filter(r)]
                    if preferred:
                        chosen = preferred[0]
                if chosen is None:
                    chosen = roots[0]
                creators_to_prepend.append(chosen)
                seq_set.add(chosen)
                # Mark this handle (and any others the chosen creator
                # DEFs in the same call) as produced so we don't re-graft.
                chosen_eff = self.graph.effect(chosen)
                if chosen_eff is not None:
                    produced.update(chosen_eff.def_)
                else:
                    produced.add(h)
            for h in eff.def_:
                produced.add(h)
        if not creators_to_prepend:
            return None
        return creators_to_prepend + list(sequence)

    def post_parse_extensions(
        self,
        sequence: List[str],
        depth: int = 2,
        branching: int = 4,
        acceptance_threshold: float = 0.0,
    ) -> List[List[str]]:
        """Generate downstream consumer-chain extensions of ``sequence``.

        For each handle still live at the end of ``sequence``, append APIs
        that USE that handle, recursing up to ``depth`` with ``branching``
        candidates per step. Each extension is filtered by:

          1. Typestate validity (no USE_BEFORE_INIT / DOUBLE_DESTROY etc.).
             UNCLOSED_RESOURCE is tolerated as a trailing artifact — fuzz
             drivers' outer scope owns final cleanup.
          2. Optional acceptance threshold against the merged automaton.
             ``acceptance_threshold=0.0`` (default) means no filter, so
             projects with no learned automaton don't lose extensions.

        Returns full extended sequences (``sequence ++ chain``), deduped.
        ``[]`` when no graph is attached, no handle is live at the tail, or
        no feasible chain exists.

        Reuses ``UseDefGraph.consumers`` + ``Typestate.check`` — no new
        heuristic. The returned set composes with the L4 candidate pool the
        same way ``sample_accepting_paths`` and ``graft_creator_prefix`` do.
        """
        if self.graph is None or not sequence:
            return []
        typestate = Typestate(self.graph)
        raw = extend_post_def(
            self.graph, typestate, sequence,
            depth=depth, branching=branching,
        )
        if acceptance_threshold > 0.0:
            return [r for r in raw
                    if self.acceptance_score(r) >= acceptance_threshold]
        return raw

    def acceptance_score(self, sequence: List[str]) -> float:
        """Score a candidate API call sequence against the merged automaton.

        Returns a value in ``[0.0, 1.0]``:

        - ``1.0``: every step's API has a matching outgoing edge label in the
          merged automaton, walking from the root.
        - intermediate: fraction of the prefix that walks before getting stuck.
        - ``0.0``: the very first call has no matching transition.

        Used as a soft signal in L4 ranking — high-acceptance sequences
        reflect the project's actual usage patterns. Note: matching is by
        ``api_name`` only (not full edge label including binding pattern), so
        a sequence that the project uses with different binding shapes still
        scores 1.0. This is intentional — L4 ranks API order, not binding.

        Adjacency dict is cached per (pta_size, n_merged_states) version so
        L4 calling this for every candidate doesn't re-pay O(|nodes|) build
        cost per call.
        """
        if not sequence or self.pta.size() == 0:
            return 0.0
        # Build (or reuse) per-equivalence-class api_name → next_rep adjacency.
        version_key = (self.pta.size(), self.n_merged_states)
        cached = getattr(self, "_acceptance_score_adj_cache", None)
        if cached is not None and cached[0] == version_key:
            adj = cached[1]
        else:
            adj = {}
            for nid, node in self.pta.nodes.items():
                rep = self.edsm.uf.find(nid)
                outs = adj.setdefault(rep, {})
                for (api, _bp), child_id in node.children.items():
                    # First match wins; subsequent collisions ignored — this
                    # is acceptable because identical equivalence classes
                    # share outgoing API names by construction.
                    outs.setdefault(api, self.edsm.uf.find(child_id))
            object.__setattr__(
                self, "_acceptance_score_adj_cache", (version_key, adj))
        cur = self.edsm.uf.find(0)
        steps_walked = 0
        for api in sequence:
            outs = adj.get(cur)
            if outs is None:
                break
            nxt = outs.get(api)
            if nxt is None:
                break
            cur = nxt
            steps_walked += 1
        return steps_walked / len(sequence)

    def to_summary(self) -> Dict[str, Any]:
        return {
            "project": self.project,
            "files_parsed": self.n_files_parsed,
            "traces": self.n_traces,
            "pta_states": self.n_pta_states,
            "merged_states": self.n_merged_states,
            "compression_ratio": (
                round(self.n_merged_states / self.n_pta_states, 4)
                if self.n_pta_states else 0.0
            ),
            "oracle_calls": self.n_oracle_calls,
            "handle_binding_hit_rate": round(self.handle_binding_hit_rate, 3),
            "acceptance_rate": round(self.acceptance_rate(), 3),
        }


# ----------------------------------------------------------------------- driver


def learn_project_automaton(
    project: str,
    source_root: Path,
    consumer_paths: List[str],
    project_apis: List[Dict[str, Any]],
    output_dir: Path,
    library_purpose: str = "",
    include_dirs: Optional[List[Path]] = None,
    enable_llm_oracle: bool = False,
    oracle_model: str = "gpt-4o-mini",
    min_score_to_merge: float = 1.5,
) -> AutomatonArtifact:
    # Default ``enable_llm_oracle=False`` matches the production policy
    # documented in CLAUDE.md ("Open TODOs": oracle off in production
    # until cost-aware pacing lands). Previously defaulted to True, which
    # only worked because the sole live caller (data_context.py Step 5e2)
    # always passed False explicitly. Aligning the default removes a
    # foot-gun for any new caller.
    """End-to-end: extract traces, build PTA, run EDSM (with optional oracle),
    persist all intermediate artifacts under ``output_dir``.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Inputs we share with EntryPointAnalyzer for handle classification.
    from liberator_adapter.constraints.entry_point_analyzer import EntryPointAnalyzer
    classifier = EntryPointAnalyzer()
    api_set = {a["function_name"] for a in project_apis if a.get("function_name")}
    handle_arg_idx_map: Dict[str, Set[int]] = {}
    for api in project_apis:
        name = api.get("function_name") or ""
        if not name:
            continue
        idxs = {
            i for i, arg in enumerate(api.get("arguments", []) or [])
            if classifier._is_handle_type(
                arg.get("type") or arg.get("type_clang") or "")
        }
        if idxs:
            handle_arg_idx_map[name] = idxs

    # 1. Extract static traces.
    logger.info("[%s] extracting static traces...", project)
    trace_report: ProjectTraceReport = extract_project_traces(
        project=project,
        source_root=source_root,
        consumer_paths=consumer_paths,
        public_apis=api_set,
        handle_arg_idx_map=handle_arg_idx_map,
        include_dirs=include_dirs or [],
        sample_size=10**6,  # keep all
    )
    traces: List[StaticTrace] = trace_report.sample_traces
    (output_dir / "traces.json").write_text(
        json.dumps([t.to_dict() for t in traces], indent=2)
    )
    logger.info("[%s] traces=%d, calls=%d, handle_bind%%=%.1f",
                project, trace_report.n_traces, trace_report.n_total_calls,
                trace_report.handle_binding_hit_rate * 100)

    # 2. Use-def graph + APIEffects (consumed by PTA for typestate vector).
    # Pipe in L2 LifecycleAnalyzer pairs as KILL effects so destroyer APIs
    # transition handles to DESTROYED rather than leaving them INITIALIZED
    # (P1 carryover). The pair shape is (init_api, destroy_api); per the
    # extract_api_effects contract this propagates ``init.def_`` into
    # ``destroy.kill``.
    lifecycle_pairs: List[Tuple[str, str]] = []
    try:
        from liberator_adapter.constraints import analyze_lifecycle
        lc_analysis = analyze_lifecycle(project_apis)
        for pair in lc_analysis.pairs:
            init_name = getattr(pair, "init_api", "") or ""
            destroy_name = getattr(pair, "destroy_api", "") or ""
            if init_name and destroy_name:
                lifecycle_pairs.append((init_name, destroy_name))
        logger.info("[%s] lifecycle pairs piped in as KILL effects: %d",
                    project, len(lifecycle_pairs))
    except Exception as exc:
        logger.warning("[%s] lifecycle inference failed (non-critical): %s",
                       project, exc)

    effects = extract_api_effects(
        project_apis,
        lifecycle_pairs=lifecycle_pairs,
        consumed_handle_keys=classifier._consumed_handle_keys,
        extract_produced_handles=classifier._extract_produced_handles,
        normalize_handle_type=classifier._normalize_handle_type,
    )
    graph = UseDefGraph(effects)

    # 3. PTA.
    logger.info("[%s] building PTA...", project)
    pta = build_pta(traces, graph)
    (output_dir / "pta.json").write_text(json.dumps(pta.to_dict(), indent=2))
    logger.info("[%s] PTA: %d nodes, %d edges", project, pta.size(), pta.edges())

    # 4. EDSM merge (with LLM oracle if enabled).
    oracle_obj: Optional[LLMEquivalenceOracle] = None
    oracle_fn = None
    if enable_llm_oracle:
        oracle_obj = LLMEquivalenceOracle(
            library_name=project,
            library_purpose=library_purpose,
            model_name=oracle_model,
            cache_path=output_dir / "oracle_cache.json",
        )
        oracle_fn = oracle_obj.query
    logger.info("[%s] running EDSM (oracle=%s)...", project,
                "LLM" if oracle_fn else "evidence-only")
    edsm_result = merge(
        pta=pta,
        oracle=oracle_fn,
        library_name=project,
        library_purpose=library_purpose,
        min_score_to_merge=min_score_to_merge,
    )
    (output_dir / "merged.json").write_text(
        json.dumps(edsm_result.to_dict(), indent=2)
    )
    logger.info("[%s] EDSM: %d → %d states (oracle yes=%d, no=%d, ?=%d)",
                project,
                edsm_result.n_input_states, edsm_result.n_output_states,
                edsm_result.n_oracle_yes, edsm_result.n_oracle_no,
                edsm_result.n_oracle_uncertain)

    artifact = AutomatonArtifact(
        project=project,
        n_files_parsed=trace_report.n_files_parsed,
        n_traces=trace_report.n_traces,
        n_pta_states=pta.size(),
        n_merged_states=edsm_result.n_output_states,
        n_oracle_calls=(oracle_obj.stats()["llm_calls"] if oracle_obj else 0),
        handle_binding_hit_rate=trace_report.handle_binding_hit_rate,
        output_dir=output_dir,
        pta=pta,
        edsm=edsm_result,
        graph=graph,
        project_apis=project_apis,
    )
    (output_dir / "metadata.json").write_text(
        json.dumps(artifact.to_summary(), indent=2)
    )
    return artifact
