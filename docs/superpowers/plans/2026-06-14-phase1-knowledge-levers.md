# Phase 1 — Knowledge Levers (L1/L6/L7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) tracking. All levers ship **gated default-off** for clean A/B (baseline = gate off).

**Goal:** Lift generated-driver coverage toward / past PromeFuzz by making the reconciled `APISemanticModel` *dictate* which objects to construct (L1), with what values (L6), in what order + breadth (L7). Phase 0 (tooling) already landed and is validated (c-ares compile-gate 0→13).

**Architecture:** Three independent, gated levers, each a deterministic change feeding existing machinery (sequence_constructor / coverage_ranker / hole_semantics). No new LLM calls. Each is A/B-controlled by a `LOGICFUZZ_*` env gate, default-off.

**Spec:** `docs/superpowers/specs/2026-06-13-knowledge-driven-coverage-optimization-design.md` §5 Phase 1.

**Ground-truth:** captured by three investigation agents (2026-06-14) — verbatim change-sites + failing-test shapes embedded in the implementation workflow.

---

## Levers, gates, change-sites

### L1 — Object-construction-first root ranking (`LOGICFUZZ_OBJCONSTRUCT_FIRST`)
THE top coverage lever (lcms parser drivers plateau ~79 edges; PromeFuzz is 83/141 object-construction). It REBALANCES an existing explicit parser-first bias — not a new idea. `_root_kind(sem)` ∈ {parser_entry, data_buildable, caller_alloc, other} is pure over `APISemantics.role` + `args[*].role`.
- **L1a:** add `_root_kind` + the gate in `sequence_constructor.py`.
- **L1b:** apply preference at: `sequence_constructor._creator_key`/`_recovered_key` (~598-617, invert `is_entry`), `construct_sequences` target_pool (~795-803, data-buildable creators first), `data_context.py` strand order (~1349-1363, `_gap_ranked` before `_buffer_ranked`), portfolio buckets (~1942, `[_bB,_bC,_bA]`). ">=1 parser per parser-only subsystem" is automatic (cluster-cover invariant).

### L6 — Value-domains dictate leaf holes (`LOGICFUZZ_VALUE_DOMAINS`)
- **L6a:** `named_constants.extract_constant_vocabulary` — add a `#define NAME 0x????????` (4cc) pass not subject to `_MIN_GROUP`; `hole_semantics._arg_intent` — when `members` empty but type looks like enum/signature, return intent that FORBIDS `(Enum)(data%N)` and demands legal-set indexing.
- **L6b:** carry `@param.text`: add `_DocEvidence.arg_texts` (`api_semantic_model.collect_doc_evidence` ~468-475, stop discarding `p["text"]`) → `ArgSemantic.doc_text` (via `reconcile`) → `_arg_intent` regex-mines a documented numeric range into the FUZZ_DERIVE text. Also fix `data_context.py:2061` to pass `doc_signals=` to `extract_error_contracts` (pre-existing @return wiring bug).
- **L6c:** header-facts (`header_facts.literal_for`) already wired (Phase 0) — confirm only.

### L7 — OrderSets + ALL-COVER floor (`LOGICFUZZ_ORDERSETS`, `LOGICFUZZ_API_FLOOR`)
- **L7a:** new `liberator_adapter/analysis/order_sets.py` = verbatim port of PromeFuzz `OrderSet.from_order_list` + `OrderSetCollection.minimize` (`/tmp/promefuzz_ref/src/preprocessor/consumer.py:375-421,514-566`) over `List[str]`; wire (3 lines, gated) at `data_context.py:~1251` to `normalize+minimize` `_accept` before `construct_sequences`. We ALREADY extract the ordered raw traces (`static_trace`); this normalizes them.
- **L7b:** Phase-1b API-floor pass in `coverage_ranker._coverage_complete_select` (after `n_cover=len(selected)`, ~509): greedy set-cover so every constructable API in the pool appears in ≥1 selected sequence; surface `api_floor_residual_count` in stats. (Skip PromeFuzz's online loop — that's F6.)

---

## Tasks (TDD, one commit each, gates default-off)

1. **L1a** `_root_kind` classifier + `LOGICFUZZ_OBJCONSTRUCT_FIRST` gate — `tests/test_p3_objconstruct_first.py` (root_kind unit tests).
2. **L1b** apply object-construction-first preference at the 4 sites — same test file (gate on/off ordering + parser-only-subsystem invariant).
3. **L6a** 4cc constant mine + forbid enum arithmetic — `tests/test_p3_value_domains.py` (4cc capture; enum-typed arg forbids `%N`).
4. **L6b** `@param.text` → `doc_text` → range-mined intent + `doc_signals=` wiring — same test file (param.text survives; documented range reaches intent; missing-doc_text safe).
5. **L7a** `order_sets.py` port + gated wire — `tests/test_p1_order_sets.py` (split/minimize/end-to-end).
6. **L7b** API-floor pass — `tests/test_p1_api_floor.py` (floor off default; floor-on covers orphan API; residual reporting).
7. **Verification + A/B** — full `pytest`; lcms gated re-measure (all gates on) vs baseline (gates off); record merged branch delta. Compare to PromeFuzz lcms (4560 br / 358 API).

## A/B measurement
Baseline run: all gates off (current behavior). Treatment: `LOGICFUZZ_OBJCONSTRUCT_FIRST=1 LOGICFUZZ_VALUE_DOMAINS=1 LOGICFUZZ_ORDERSETS=1 LOGICFUZZ_API_FLOOR=1`. Metric: merged-harness branch coverage + distinct invoked APIs + per-driver edges (break past the 79 ceiling) + FP/crash count. Target: close toward PromeFuzz on lcms-class libs.

## Risks
- L1 over-constructs objects needing a valid sub-component → paired with L6 valid values; ≥1 parser/subsystem kept.
- L6 over-pins constants → derive *within* the documented range (FUZZABLE diversity).
- Each gate independently A/B-able to attribute gains.
