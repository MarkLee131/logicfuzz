"""Run the static trace extractor on the four projects we have OSS-Fuzz src
extracted for and emit a per-project + aggregate signal-quality report.

Usage:
    python3 -m tools.p0_trace_survey.run_survey

Outputs:
    results/p0_trace_signal_report.json
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Set

# Allow running as `python3 tools/p0_trace_survey/run_survey.py` from repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.p0_trace_survey.extract_traces import (
    ProjectTraceReport,
    extract_project_traces,
)

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")


# Projects we have local OSS-Fuzz source for, with their consumer paths.
# Paths are relative to the project's source root (results/{p}/src_ossfuzz/{p}).
PROJECTS = {
    "libucl": {
        "src_root": REPO_ROOT / "results" / "libucl" / "src_ossfuzz" / "libucl",
        "consumer_paths": ["tests"],
        "include_dirs": ["include", "src"],
    },
    "sqlite3": {
        # sqlite3 src is special: amalgamation, no traditional tests/ dir.
        # OSS-Fuzz container has tests at /src/sqlite3/test/ — but our
        # extraction may have it under a different name. Try several.
        "src_root": REPO_ROOT / "results" / "sqlite3" / "src_ossfuzz" / "sqlite3",
        "consumer_paths": ["test", "ext", "tool"],
        "include_dirs": ["."],
    },
    "c-ares": {
        "src_root": REPO_ROOT / "results" / "c-ares" / "src_ossfuzz" / "c-ares",
        "consumer_paths": ["test"],
        "include_dirs": ["include", "src/lib"],
    },
    "libaom": {
        "src_root": REPO_ROOT / "results" / "libaom" / "src_ossfuzz" / "libaom",
        "consumer_paths": ["test", "examples", "apps"],
        "include_dirs": [".", "test"],
    },
}


def _load_public_apis(project: str) -> Set[str]:
    p = REPO_ROOT / "results" / project / "static_analysis" / "project_apis.json"
    if not p.exists():
        return set()
    payload = json.loads(p.read_text())
    apis = payload["apis"] if isinstance(payload, dict) and "apis" in payload else payload
    return {a.get("function_name", "") for a in apis if a.get("function_name")}


def _load_handle_arg_idx_map(project: str) -> Dict[str, Set[int]]:
    """For each public API, the set of arg indices whose declared type is a
    handle (opaque pointer / typedef). Computed via the same classifier used
    by EntryPointAnalyzer so the metric is consistent with downstream wiring.
    """
    p = REPO_ROOT / "results" / project / "static_analysis" / "project_apis.json"
    if not p.exists():
        return {}
    payload = json.loads(p.read_text())
    apis = payload["apis"] if isinstance(payload, dict) and "apis" in payload else payload

    from liberator_adapter.constraints.entry_point_analyzer import EntryPointAnalyzer
    classifier = EntryPointAnalyzer()
    out: Dict[str, Set[int]] = {}
    for api in apis:
        name = api.get("function_name") or ""
        if not name:
            continue
        idxs: Set[int] = set()
        for i, arg in enumerate(api.get("arguments") or []):
            arg_type = arg.get("type") or arg.get("type_clang") or ""
            if classifier._is_handle_type(arg_type):
                idxs.add(i)
        if idxs:
            out[name] = idxs
    return out


def _resolve_includes(src_root: Path, rels: List[str]) -> List[Path]:
    out = []
    for r in rels:
        p = (src_root / r).resolve()
        if p.exists():
            out.append(p)
    return out


def _summary_table(reports: Dict[str, ProjectTraceReport]) -> str:
    lines = []
    lines.append(f'{"project":10} {"#files":>7} {"#funcs":>7} {"#traces":>8} '
                 f'{"#calls":>7} {"#APIs":>6} {"p50":>4} {"max":>4} '
                 f'{"all_arg%":>9} {"handle%":>8}')
    lines.append("-" * 84)
    for proj, r in reports.items():
        lines.append(
            f'{proj:10} {r.n_files_parsed:>7} {r.n_functions_visited:>7} '
            f'{r.n_traces:>8} {r.n_total_calls:>7} {r.n_unique_apis_called:>6} '
            f'{r.api_calls_per_trace_p50:>4} {r.api_calls_per_trace_max:>4} '
            f'{r.binding_hit_rate*100:>8.1f}% {r.handle_binding_hit_rate*100:>7.1f}%'
        )
    return "\n".join(lines)


def _exit_check(reports: Dict[str, ProjectTraceReport]) -> str:
    """P0 exit criteria (now production-aligned, see docs/automaton.md §7):
       - per-project trace count ≥ 10
       - value-flow binding hit rate (handle args only) ≥ 80%
    """
    msgs = []
    for proj, r in reports.items():
        ok_traces = r.n_traces >= 10
        ok_bind = r.handle_binding_hit_rate >= 0.80
        msgs.append(
            f'  {proj}: '
            f'traces={r.n_traces} ({"PASS" if ok_traces else "FAIL"} ≥10),  '
            f'handle_binding={r.handle_binding_hit_rate*100:.1f}% '
            f'({"PASS" if ok_bind else "FAIL"} ≥80%);  '
            f'all-arg bind={r.binding_hit_rate*100:.1f}% (informational)'
        )
    return "\n".join(msgs)


def main() -> int:
    out_dir = REPO_ROOT / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "p0_trace_signal_report.json"

    reports: Dict[str, ProjectTraceReport] = {}
    aggregate_payload: Dict[str, dict] = {}

    for proj, cfg in PROJECTS.items():
        src_root: Path = cfg["src_root"]
        if not src_root.exists():
            print(f"[skip] {proj}: source root missing at {src_root}")
            continue
        public_apis = _load_public_apis(proj)
        if not public_apis:
            print(f"[skip] {proj}: no project_apis.json found")
            continue
        handle_arg_idx_map = _load_handle_arg_idx_map(proj)
        include_dirs = _resolve_includes(src_root, cfg.get("include_dirs", []))
        n_handle_apis = sum(1 for v in handle_arg_idx_map.values() if v)
        print(f"[run]  {proj}: src={src_root}, "
              f"public_api_count={len(public_apis)}, "
              f"apis_with_handle_args={n_handle_apis}, "
              f"includes={[str(p.relative_to(src_root)) for p in include_dirs]}")
        try:
            r = extract_project_traces(
                project=proj,
                source_root=src_root,
                consumer_paths=cfg["consumer_paths"],
                public_apis=public_apis,
                handle_arg_idx_map=handle_arg_idx_map,
                include_dirs=include_dirs,
            )
        except Exception as e:
            print(f"[err]  {proj}: extractor raised: {e}")
            continue
        reports[proj] = r
        aggregate_payload[proj] = r.to_dict()

    # Persist + summarize.
    out_path.write_text(json.dumps(aggregate_payload, indent=2))
    print()
    print("=== summary ===")
    print(_summary_table(reports))
    print()
    print("=== P0 exit criteria ===")
    print(_exit_check(reports))
    print()
    print(f"Full report: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
