"""T8 probe: confirm the automaton trace extractor learns the project's OWN
OSS-Fuzz driver sequences. Offline (cached results/<proj>/). Usage:
  PYTHONPATH=. python3 scripts/t8_driver_traces_probe.py c-ares"""
import json, sys
from pathlib import Path
from liberator_adapter.analysis.static_trace import extract_project_traces
from src.context.data_context import _resolve_drivers_root

P = sys.argv[1] if len(sys.argv) > 1 else "c-ares"
def load(p):
    t = open(p).read().strip()
    try:
        d = json.loads(t); return d.get('apis', d) if isinstance(d, dict) else d
    except json.JSONDecodeError:
        return [json.loads(l) for l in t.splitlines() if l.strip()]
apis = load(f"results/{P}/apis_llvm.json")
public = {a["function_name"] for a in apis if a.get("function_name")}
src_root = Path(f"results/{P}/src_ossfuzz/{P}")
drv = _resolve_drivers_root(P)
inc = [(src_root / d).resolve() for d in ("include", "src", "lib", ".") if (src_root / d).exists()]
rep = extract_project_traces(project=P, source_root=src_root,
                             consumer_paths=[str(drv.resolve())], public_apis=public, include_dirs=inc)
print(f"{P}: files={rep.n_files_parsed}/{rep.n_files_attempted} traces={rep.n_traces} "
      f"unique_apis={rep.n_unique_apis_called}")
for t in rep.sample_traces:
    pub = [c.api_name for c in t.api_calls if c.api_name in public]
    if pub:
        print(f"  {t.function_name}: {' -> '.join(pub)}")
