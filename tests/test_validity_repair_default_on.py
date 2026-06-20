"""Regression: the universal validity-repair net must run at skeleton synthesis
BY DEFAULT (no ``LOGICFUZZ_*`` env set); the data_context gate delegates to the
constructor's ``_validity_contract()`` SSOT so the four sites can't drift apart.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.context import data_context as dc
from liberator_adapter.analysis import sequence_constructor as sc


def test_validity_repair_enabled_by_default(monkeypatch):
    # No env set must still leave the repair net ON (regression: gate defaulted OFF).
    monkeypatch.delenv("LOGICFUZZ_VALIDITY_CONTRACT", raising=False)
    assert dc._validity_repair_enabled() is True


def test_validity_repair_gate_tracks_constructor_contract(monkeypatch):
    # Drift guard: the data_context gate is the SAME decision as the constructor's
    # _validity_contract() SSOT regardless of env, so the bug can't recur.
    monkeypatch.delenv("LOGICFUZZ_VALIDITY_CONTRACT", raising=False)
    assert dc._validity_repair_enabled() == sc._validity_contract()
    # Even a stale =0 cannot desync this site from the (unconditional) contract.
    monkeypatch.setenv("LOGICFUZZ_VALIDITY_CONTRACT", "0")
    assert dc._validity_repair_enabled() == sc._validity_contract()
