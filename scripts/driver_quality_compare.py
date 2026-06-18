#!/usr/bin/env python3
"""Driver-quality comparison: LogicFuzz (ours) vs PromeFuzz.

Static, no-run analysis answering three questions for the eval pitch:
  1. BREADTH  — do we cover (nearly) all fuzzable APIs of the project?
  2. DEPTH    — coverage-per-driver / APIs-per-driver (shallow vs deep).
  3. QUALITY  — API-misuse / false-positive crashes (PromeFuzz's own FP vs TP triage).

Sources (read-only):
  ours      : results/<proj>/static_analysis/analysis_summary.json
              results/<proj>/static_analysis/redundancy_telemetry.json
  promefuzz : /tmp/promefuzz_ref/examples/<proj>/synthesized/*.{c,cpp}  (target-API header comment)
              /tmp/promefuzz_ref/examples/<proj>/report/*.log.md        (FP-/TP- crash triage)

Usage: python3 scripts/driver_quality_compare.py [--json out.json]
"""
from __future__ import annotations
import json, re, glob, argparse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PF_ROOT = Path("/tmp/promefuzz_ref/examples")

# project name mapping: our results dir <-> promefuzz examples dir
SHARED = {
    "cjson": "cjson", "c-ares": "c-ares", "lcms": "lcms",
    "zlib": "zlib", "libpng": "libpng", "sqlite3": "sqlite3",
}

HDR_FN = re.compile(r"^//\s+([A-Za-z_][A-Za-z0-9_]*)\s+at\s+", re.M)
CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def pf_project(proj: str) -> dict:
    """Analyze PromeFuzz synthesized corpus for one project."""
    d = PF_ROOT / proj / "synthesized"
    files = sorted(glob.glob(str(d / "*.c")) + glob.glob(str(d / "*.cpp")))
    union_apis: set[str] = set()
    per_driver_apis: list[int] = []
    per_driver_callsites: list[int] = []
    per_driver_loc: list[int] = []
    for f in files:
        src = Path(f).read_text(errors="replace")
        # declared target APIs from the header comment block
        targets = set(HDR_FN.findall(src))
        union_apis |= targets
        per_driver_apis.append(len(targets))
        # actual call sites of those declared APIs in the body
        body_calls = CALL.findall(src)
        per_driver_callsites.append(sum(1 for c in body_calls if c in targets))
        per_driver_loc.append(src.count("\n") + 1)

    # crash triage from report/
    rep = PF_ROOT / proj / "report"
    fp = tp = 0
    fp_kinds, tp_kinds = [], []
    if rep.is_dir():
        for r in rep.iterdir():
            name = r.name
            if name.startswith("FP-"):
                fp += 1; fp_kinds.append(name.split("@")[0])
            elif name.startswith("TP-"):
                tp += 1; tp_kinds.append(name.split("@")[0])

    n = len(files) or 1
    return {
        "n_drivers": len(files),
        "union_target_apis": len(union_apis),
        "mean_apis_per_driver": round(sum(per_driver_apis) / n, 2),
        "mean_callsites_per_driver": round(sum(per_driver_callsites) / n, 2),
        "mean_loc": round(sum(per_driver_loc) / n, 1),
        "report_fp": fp, "report_tp": tp,
        "fp_kinds": fp_kinds, "tp_kinds": tp_kinds,
        "_union_set": union_apis,
    }


def ours_project(proj: str) -> dict:
    sa = REPO / "results" / proj / "static_analysis"
    summ = sa / "analysis_summary.json"
    out: dict = {}
    if summ.is_file():
        d = json.loads(summ.read_text())
        st = d.get("statistics", {})
        g2 = d.get("grammar_info", {}).get("g2_construction", {})
        flt = d.get("grammar_info", {}).get("filter", {}).get("stats", {})
        out.update({
            "total_apis": st.get("total_apis"),
            # api_coverage = distinct APIs across ALL constructed sequences = THE breadth metric.
            # (gap_apis_reached is only the baseline-uncovered G5 subset — do NOT use for breadth.)
            "breadth_api_coverage": g2.get("api_coverage"),
            "gap_reached": g2.get("gap_apis_reached"),
            "gap_total": g2.get("gap_apis_total"),
            "selected_apis": flt.get("api_coverage_count"),
            "avg_seq_len": g2.get("avg_length"),
            "n_densified": g2.get("n_densified"),
        })
    red = sa / "redundancy_telemetry.json"
    if red.is_file():
        r = json.loads(red.read_text())
        out.update({
            "n_drivers": r.get("n_drivers"),
            "union_apis": r.get("union_apis"),
            "mean_pairwise_jaccard": r.get("mean_pairwise_jaccard") or r.get("portfolio_redundancy", {}).get("mean_pairwise_jaccard"),
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write machine-readable result here")
    args = ap.parse_args()

    rows = {}
    for ours_name, pf_name in SHARED.items():
        rows[ours_name] = {
            "ours": ours_project(ours_name),
            "promefuzz": pf_project(pf_name),
        }

    # ---- human-readable tables ----
    print("=" * 100)
    print("BREADTH — fuzzable-API coverage (do we cover all the APIs?)")
    print("=" * 100)
    print(f"{'project':10} | {'API ceiling':>11} | {'OURS reached':>14} | {'PF union tgt':>12} | {'OURS sel-union':>14}")
    print("-" * 80)
    for p, r in rows.items():
        o, pf = r["ours"], r["promefuzz"]
        ceil = o.get("total_apis")
        reached = o.get("breadth_api_coverage")
        rpct = f"{reached}/{ceil} ({100*reached/ceil:.0f}%)" if ceil and reached else "n/a"
        print(f"{p:10} | {str(ceil):>11} | {rpct:>14} | {str(pf['union_target_apis']):>12} | {str(o.get('union_apis')):>14}")
    print("WARN: results/<proj>/static_analysis/analysis_summary.json may be STALE.")
    print("      Regenerate fresh with: LOGICFUZZ_NO_CACHE=1 python3 scripts/measure_breadth.py comparison/<proj>.yaml")

    print()
    print("=" * 100)
    print("DEPTH — per-driver richness (shallow vs deep)")
    print("=" * 100)
    print(f"{'project':10} | {'OURS #drv':>9} {'avg seq len':>11} | {'PF #drv':>7} {'PF apis/drv':>11} {'PF calls/drv':>12} {'PF loc':>7}")
    print("-" * 90)
    for p, r in rows.items():
        o, pf = r["ours"], r["promefuzz"]
        print(f"{p:10} | {str(o.get('n_drivers')):>9} {str(o.get('avg_seq_len')):>11} | "
              f"{pf['n_drivers']:>7} {pf['mean_apis_per_driver']:>11} {pf['mean_callsites_per_driver']:>12} {pf['mean_loc']:>7}")

    print()
    print("=" * 100)
    print("QUALITY — PromeFuzz's OWN crash triage (FP = driver API-misuse, TP = real lib bug)")
    print("=" * 100)
    tot_fp = tot_tp = 0
    for p in SHARED:
        pf = rows[p]["promefuzz"]
        tot_fp += pf["report_fp"]; tot_tp += pf["report_tp"]
        print(f"{p:10} | FP={pf['report_fp']} {pf['fp_kinds']}  TP={pf['report_tp']} {pf['tp_kinds']}")
    print("-" * 60)
    print(f"shared-proj totals: FP(driver-misuse)={tot_fp}  TP(real-bug)={tot_tp}")
    print("NOTE: report/ holds only the crashes PromeFuzz surfaced after its sanitizer-repair loop;")
    print("      see scripts/driver_quality_compare.py header for the full 22-project FP/TP tally.")

    if args.json:
        for r in rows.values():
            r["promefuzz"].pop("_union_set", None)
        Path(args.json).write_text(json.dumps(rows, indent=2))
        print(f"\n[wrote {args.json}]")


if __name__ == "__main__":
    main()
