"""Disk-backed cache for comprehension artifacts.

Layout:
    results/{project}/comprehension/
        purpose.txt
        api_usage.json          # {api_name: usage_text}
        sequences.json          # [{key, status, diagnosis, repair, invariants}]

Keys are content-hashed so source changes invalidate stale entries automatically.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _hash_key(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()[:16]


class KnowledgeCache:
    """Lightweight per-project cache for the comprehender."""

    def __init__(self, project: str, root: Optional[Path] = None):
        self.project = project
        base = Path(root) if root else Path("./results") / project
        self.dir = base / "comprehension"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.purpose_path = self.dir / "purpose.txt"
        self.api_path = self.dir / "api_usage.json"
        self.seq_path = self.dir / "sequences.json"

    # ---- library purpose ----
    def load_purpose(self) -> Optional[str]:
        if not self.purpose_path.exists():
            return None
        try:
            return self.purpose_path.read_text(encoding="utf-8").strip() or None
        except OSError as exc:
            logger.warning("Failed to read purpose cache: %s", exc)
            return None

    def save_purpose(self, purpose: str) -> None:
        try:
            self.purpose_path.write_text(purpose, encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to write purpose cache: %s", exc)

    # ---- per-API usage ----
    def load_api_usages(self) -> Dict[str, str]:
        if not self.api_path.exists():
            return {}
        try:
            data = json.loads(self.api_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to read api_usage cache: %s", exc)
            return {}

    def save_api_usages(self, usages: Dict[str, str]) -> None:
        try:
            self.api_path.write_text(
                json.dumps(usages, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Failed to write api_usage cache: %s", exc)

    # ---- sequence semantics ----
    @staticmethod
    def sequence_key(seq: List[str]) -> str:
        return _hash_key("seq", "|".join(seq))

    def load_sequence_semantics(self) -> Dict[str, Dict[str, Any]]:
        if not self.seq_path.exists():
            return {}
        try:
            data = json.loads(self.seq_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to read sequence cache: %s", exc)
            return {}

    def save_sequence_semantics(self, semantics: Dict[str, Dict[str, Any]]) -> None:
        try:
            self.seq_path.write_text(
                json.dumps(semantics, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Failed to write sequence cache: %s", exc)
