"""Regression: the universal validity-repair net (``repair_sequence_validity``)
must run at skeleton synthesis BY DEFAULT — i.e. with no ``LOGICFUZZ_*`` env set.

Root cause (verified 2026-06-20): graduation commit ac65481e made
``_validity_contract()`` unconditional in the constructor / CBFactory /
skeleton_generator but MISSED the only production call site of the universal net,
``src/context/data_context.py`` (``_synthesize_skeletons_per_sequence``), which
kept an independent env-gate defaulting OFF
(``os.environ.get("LOGICFUZZ_VALIDITY_CONTRACT", "")``). So in every default run
the floor / densified / RESIDUAL_ALLCOVER single-API sequences reached skeleton
synthesis UNREPAIRED — their ``nullable=False`` opaque handles stayed NULL →
Task-11 guard → dead driver — despite CLAUDE.md/docstrings claiming the contract
is unconditional.

The fix makes the data_context gate DELEGATE to the constructor's
``_validity_contract()`` SSOT so the four VALIDITY_CONTRACT sites can never drift
apart again.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.context import data_context as dc
from liberator_adapter.analysis import sequence_constructor as sc


def test_validity_repair_enabled_by_default(monkeypatch):
    # A default run sets no LOGICFUZZ_VALIDITY_CONTRACT; the universal repair net
    # must still be ON. This is the regression: the gate defaulted OFF.
    monkeypatch.delenv("LOGICFUZZ_VALIDITY_CONTRACT", raising=False)
    assert dc._validity_repair_enabled() is True


def test_validity_repair_gate_tracks_constructor_contract(monkeypatch):
    # Drift guard: the data_context skeleton-synthesis gate is the SAME decision
    # as the constructor's _validity_contract() SSOT, regardless of env — so a
    # re-introduced independent env-default-OFF read (the exact bug) can never
    # again leave the four VALIDITY_CONTRACT sites inconsistent.
    monkeypatch.delenv("LOGICFUZZ_VALIDITY_CONTRACT", raising=False)
    assert dc._validity_repair_enabled() == sc._validity_contract()
    # Even a stale =0 cannot desync this site from the (unconditional) contract.
    monkeypatch.setenv("LOGICFUZZ_VALIDITY_CONTRACT", "0")
    assert dc._validity_repair_enabled() == sc._validity_contract()
