# Driver-Generator Squeeze + Driver-Quality vs PromeFuzz — Findings

Status: 2026-06-18. Static (no-run) analysis. Reproduce:
`python3 scripts/driver_quality_compare.py --json results/driver_quality_compare.json`

Goal being evaluated:
1. Is the synthesizer "squeezed" — does it cover (nearly) all fuzzable APIs, deeply?
2. Compare driver **quality** vs PromeFuzz (not just coverage): coverage-per-driver, API-use validity, FP crashes.
3. (If quality sells) compare vs the ICSE-2025 quality-selling paper.

---

## 1. BREADTH — "do we cover all fuzzable APIs?"

> **CORRECTION (2026-06-18):** the first cut of this table used the WRONG field
> (`gap_apis_reached`, the baseline-uncovered G5 subset) AND read STALE
> `analysis_summary.json` files. The breadth metric is **`g2_construction.api_coverage`**
> (distinct APIs across all constructed sequences). A FRESH (`NO_CACHE=1`) libpng
> baseline gives **api_coverage = 208/263 (79%)**, not the stale 24/263 (9%). The
> "libpng collapse" was an artifact of stale data. Fresh per-project numbers are
> being re-measured (`scripts/measure_breadth.py`); table below pending refresh.

`breadth` = `g2_construction.api_coverage` (distinct APIs across all constructed sequences).
PF union = distinct target APIs across all PromeFuzz synthesized drivers (their `// aiming to fuzz:` headers).

| project | our API ceiling | OURS reached | PF union targets | verdict |
|---------|----------------:|-------------:|-----------------:|---------|
| cjson   | 78  | **74 (95%)** | 78  | ~parity |
| c-ares  | 138 | **120 (87%)**| 113 | **we ≥ PF** |
| zlib    | 95  | **95 (100%)**| 89  | **we ≥ PF** |
| lcms    | 297 | 116 (39%)    | **358** | **PF ≫ us** |
| sqlite3 | 258 | 62 (24%)     | **246** | **PF ≫ us** |
| libpng  | 263 | 24 (9%)      | **251** | **PF ≫ us** |

**Honest verdict:** the generator is "squeezed" **only on clean opaque-handle-lifecycle libs** (cjson/c-ares/zlib — we match or beat PF breadth). On **struct-heavy / config-heavy libs (libpng, sqlite3, lcms)** construction collapses: `reached` falls to 9–39% *and* avg sequence length drops to ~1–2 (single-API shallow drivers). This is the binding-layer ceiling (opaque-arg producers not recoverable → UNSAT → API never enters a chain). The `LOGICFUZZ_RESIDUAL_ALLCOVER` + `LOGICFUZZ_API_FLOOR` levers exist to close exactly this but were OFF in these runs — turning them on is the first "squeeze" action.

---

## 2. DEPTH — per-driver richness (REFUTES "PF is shallow")

| project | OURS avg seq len | PF apis/driver | PF callsites/driver | PF LOC |
|---------|-----------------:|---------------:|--------------------:|-------:|
| cjson   | 8.3  | 6.1 | 9.4  | 64 |
| c-ares  | 7.6  | 5.6 | 6.9  | 62 |
| zlib    | 7.6  | 6.2 | 7.8  | 62 |
| lcms    | 5.2  | **7.7** | **9.6** | 65 |
| sqlite3 | 1.4  | **7.2** | 9.4 | 62 |
| libpng  | 1.9  | **9.3** | **11.4** | 75 |

**Honest verdict — the "many but shallow" premise does NOT hold statically.** PromeFuzz drivers chain **6–9 APIs each** (deeper than ours on lcms/libpng/sqlite3). "Shallow" can only be true in the **runtime-effective** sense — a driver that calls 9 APIs but feeds random bytes that get rejected at the first gate (e.g. `cmsCreateTransform(garbage)→NULL`) executes shallowly regardless of structure. **We have not measured per-driver runtime coverage**, so this selling point is currently **unsupported**. It requires the decisive experiment below.

---

## 3. QUALITY — API-misuse / false-positive crashes

### PromeFuzz's OWN crash triage (`report/` dir: `FP-*` = driver misuse, `TP-*` = real bug)
- Shared 6 projects: **FP=4, TP=0** (c-ares, lcms, libpng, sqlite3 each retain 1 FP-* driver-misuse crash).
- Full 22-project benchmark: ~**9 FP vs ~7 TP** (e.g. lcms `FP-stack-buffer-overflow` = `cmsChangeBuffersFormat` misuse; exiv2/ffjpeg/libtiff carry real TP bugs).

**Caveat:** `report/` holds only crashes that *survived* PromeFuzz's sanitizer-repair loop. Their shipped corpus is mostly FP-free — they **pay LLM repair-loop tokens** to get there. So "PF ships lots of API-misuse crashes" is **overstated**; the defensible framing is *cost* (repair loop) vs our *by-construction* prevention.

### OUR crashers (merged preflight, the reliable signal)
`is_semantic_error` in per-trial result.json is unreliable (defaults False). Preflight accept/crash is the truth:

| project | preflight drivers | accepted | crashed (quarantined) |
|---------|------------------:|---------:|----------------------:|
| cjson   | 52  | 52  | 0 |
| libpng  | 159 | 129 | 2 |
| lcms    | 117 | 72  | 19 |
| c-ares  | 39  | 17  | 9 |
| zlib    | 8   | 0   | 0 |

**Honest verdict:** **we are not zero-FP either.** We emit driver-induced crashers (c-ares 9, lcms 19) and quarantine them pre-merge. The valid-by-construction story reduces but does not eliminate FP. A fair quality claim is **FP-rate per shipped driver after each pipeline's own filter** — measurable on both sides, and the place we likely win on efficiency (no repair loop), not on a zero.

---

## Strategic verdict

- **Breadth pitch is solid only on cjson/c-ares/zlib.** libpng/sqlite3/lcms are *losses* until the binding-layer ceiling is addressed (RESIDUAL_ALLCOVER/API_FLOOR + opaque-producer recovery). The generator is **not yet squeezed** there — this is the concrete TODO for goal item 1.
- **The driver-quality pitch (coverage-per-driver / "shallow") is RISKY as framed** and cannot be sold on static structure (PF is structurally deep). It hinges entirely on one unmeasured number: **runtime coverage-per-driver (edges hit per driver-run)**.
- **The FP/API-misuse angle is real but two-sided** — reframe as *cost-to-reach-low-FP* (repair-loop tokens vs by-construction), backed by both pipelines' FP-rate-per-shipped-driver.

## Decisive experiment (proposed)
For each shared project, build BOTH corpora under the identical cov-build and measure **per-driver edges** (sample-corpus replay, not 24h):
- coverage-per-driver distribution (median + tail) — settles "shallow?" empirically.
- union breadth at equal driver budget.
- FP-rate = crashed / shipped, per pipeline's own filter.
This is the single measurement that converts goal items 2–3 from hypothesis to evidence.

## Open input needed
Goal item 4 names an **ICSE-2025 quality-selling paper** — it is **not in this repo** (only PromeFuzz CCS'25 + Liberator are referenced). Need its identity to compare metrics.
