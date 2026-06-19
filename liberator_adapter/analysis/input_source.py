"""Symbolic materialization of fuzz bytes into an opener's input-source type.

Type-driven + library-agnostic (keys on APIRole.CREATOR + the arg type, never on
library names). FILE* is type-certain (HIGH); a CREATOR's lone const char* is a
path-or-content ambiguity (LOW -> caller wraps it in a RefineHole). FD is deferred.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Tuple
from liberator_adapter.analysis.api_semantic_model import APIRole


@dataclass
class MaterializedSource:
    stmts: List[str]
    bind_expr: str
    cleanup: List[str]
    includes: List[str]


def classify_input_source(type_str, api_role, is_input_arg: bool = True, arg_role=None) -> Optional[Tuple[str, str]]:
    role = getattr(api_role, "value", api_role)
    if role != APIRole.CREATOR.value:
        return None
    if getattr(arg_role, "value", arg_role) == "INPUT_BUFFER":
        return None
    t = (type_str or "")
    if "FILE" in t and "*" in t:
        return ("FILE_STAR", "HIGH")
    if is_input_arg and t.count("*") == 1 and "char" in t.lower():
        return ("PATH", "LOW")
    return None


def materialize(kind: str, prefix: str) -> MaterializedSource:
    if kind == "FILE_STAR":
        v = f"{prefix}_f"
        return MaterializedSource(
            stmts=[f'FILE* {v} = fmemopen((void*)data, size, "rb");',
                   f'if (!{v}) return 0;'],
            bind_expr=v, cleanup=[f'if ({v}) fclose({v});'], includes=["<stdio.h>"])
    if kind == "PATH":
        p, fd = f"{prefix}_path", f"{prefix}_fd"
        return MaterializedSource(
            stmts=[f'char {p}[] = "/tmp/lf_XXXXXX";',
                   f'int {fd} = mkstemp({p});',
                   f'if ({fd} < 0) return 0;',
                   f'write({fd}, data, size);',
                   f'close({fd});'],
            bind_expr=p, cleanup=[f'unlink({p});'],
            includes=["<stdlib.h>", "<unistd.h>"])
    raise ValueError(f"unknown input-source kind: {kind}")
