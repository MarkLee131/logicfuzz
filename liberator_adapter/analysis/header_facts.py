"""Deterministic per-(api, arg_idx) literal facts mined from headers
(e.g. ZLIB_VERSION, (int)sizeof(z_stream)). Process-global, set once, read in
the skeleton renderer — mirrors constant_usage.legal_constants_for."""
from __future__ import annotations

from typing import Dict, Optional

_FACT_MAP: Dict[str, Dict[int, str]] = {}


def set_fact_map(m: Optional[Dict[str, Dict[int, str]]]) -> None:
    global _FACT_MAP
    _FACT_MAP = m or {}


def literal_for(api_name: str, arg_idx: int) -> Optional[str]:
    try:
        return _FACT_MAP.get(api_name, {}).get(arg_idx)
    except Exception:
        return None
