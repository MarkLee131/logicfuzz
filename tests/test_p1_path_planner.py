"""Pin Phase D (Path-aware Planner) scoring and synthesis.

The Planner consumes Phase B idioms; the alignment rules here are the
public contract between Phase B distillation and Phase D planning.
Changing weights / adding new idiom kinds should keep these tests
green (the lcms-style ``context_null_pass`` test is the primary
acceptance signal for "Phase D actually does something useful").
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.state.path_planner import (  # noqa: E402
    CandidateOrigin,
    CandidatePlan,
    PathPlanner,
    PlanLedger,
    plan_and_persist,
)


# ---------------------------------------------------------------------------
# Helpers — minimal idiom-payload shape mirroring IdiomLibrary.to_dict()
# ---------------------------------------------------------------------------

def _idiom(kind, snippet, src='t.c'):
    return {
        'kind': kind, 'snippet': snippet, 'rationale': 'r',
        'source_driver': src, 'confidence': 1.0,
    }


def _payload(*idioms):
    return {'idioms': list(idioms)}


# ---------------------------------------------------------------------------
# Scoring + reordering
# ---------------------------------------------------------------------------

def test_context_null_pass_idiom_boosts_aligned_candidate():
    """The lcms-style acceptance test: ``context_null_pass`` idiom for
    ``cmsOpenProfileFromMem`` should boost any candidate containing
    that API name above an otherwise-equivalent candidate that doesn't.
    """
    p = PathPlanner(project='lcms')
    idioms = _payload(
        _idiom('context_null_pass', 'cmsOpenProfileFromMem(NULL, ...)'),
    )
    seqs = [
        ['cmsCreateTransform', 'cmsDeleteTransform'],   # 2 — short
        ['cmsOpenProfileFromMem', 'cmsCloseProfile'],   # 2 — short, aligned
    ]
    out, ledger = p.plan(seqs, idioms_payload=idioms)
    assert out[0][0] == 'cmsOpenProfileFromMem', f"aligned candidate must come first; got {out}"
    assert ledger.reordered
    assert ledger.plans[0].score > ledger.plans[1].score


def test_length_band_5_to_10_preferred():
    """Mid-length sequences get a small bonus; everything else equal,
    a 7-API sequence outranks a 2-API one."""
    p = PathPlanner(project='cjson')
    seqs = [
        ['cJSON_Parse', 'cJSON_Delete'],                  # length 2
        ['cJSON_Parse', 'cJSON_AddBoolToObject',
         'cJSON_AddItemToArray', 'cJSON_Print',
         'cJSON_Minify', 'cJSON_Compare', 'cJSON_Delete'], # length 7
    ]
    out, _ = p.plan(seqs)
    assert out[0] == seqs[1], f"5-10-length should win; got {out}"


def test_no_idioms_preserves_l4_order():
    """No idioms → no signal → stable sort keeps L4 ordering."""
    p = PathPlanner(project='unknown')
    seqs = [['a', 'b'], ['c', 'd']]
    out, ledger = p.plan(seqs, idioms_payload=None)
    assert out == seqs
    assert not ledger.reordered


def test_cleanup_pair_idiom_boosts_matching_candidate():
    p = PathPlanner(project='libfoo')
    idioms = _payload(
        _idiom('cleanup_pair', 'foo_create(...)  →  foo_destroy(...);'),
    )
    seqs = [
        ['other_api'],
        ['foo_create', 'foo_destroy'],
    ]
    out, ledger = p.plan(seqs, idioms_payload=idioms)
    assert out[0] == ['foo_create', 'foo_destroy']
    assert ledger.plans[0].matched_idioms == ['cleanup_pair']


def test_non_actionable_idiom_does_not_change_score():
    """Idioms about input *shape* (min_size_guard etc.) affect the
    Prototyper directly but don't change which candidates we pick."""
    p = PathPlanner(project='cjson')
    idioms = _payload(
        _idiom('min_size_guard', 'if (size < 8) return 0;'),
        _idiom('null_termination_required', "if (data[size-1] != '\\0') return 0;"),
    )
    seqs = [['a', 'b'], ['c', 'd']]
    _, ledger = p.plan(seqs, idioms_payload=idioms)
    for plan in ledger.plans:
        # only length-band bonus possible; either both have it or none
        assert plan.score in (0.0, 0.1)


# ---------------------------------------------------------------------------
# Synthesis: idioms implicate APIs L4 missed
# ---------------------------------------------------------------------------

def test_synthesize_missing_context_null_pass_api():
    """``context_null_pass`` idiom mentions ``cmsOpenProfileFromMem``;
    L4 didn't produce a candidate using it; project has it →
    synthesize a 1-element candidate. This is exactly the lcms recovery
    path for cmsOpenProfileFromMem that Phase A's graft couldn't fix.
    """
    p = PathPlanner(project='lcms')
    idioms = _payload(
        _idiom('context_null_pass', 'cmsOpenProfileFromMem(NULL, ...)'),
    )
    seqs = [['cmsCreateTransform', 'cmsDeleteTransform']]
    out, ledger = p.plan(
        seqs, idioms_payload=idioms,
        project_api_names={'cmsCreateTransform', 'cmsDeleteTransform',
                           'cmsOpenProfileFromMem'},
    )
    assert ['cmsOpenProfileFromMem'] in out
    assert ledger.synthesized_count == 1
    assert ledger.candidate_count_out == 2
    # The synthesized plan carries the right provenance.
    synth_plan = next(p for p in ledger.plans
                      if p.origin == CandidateOrigin.PLANNER_SYNTHESIZED)
    assert synth_plan.sequence_names == ['cmsOpenProfileFromMem']


def test_synthesize_skipped_when_idiom_api_already_covered():
    p = PathPlanner(project='lcms')
    idioms = _payload(
        _idiom('context_null_pass', 'cmsOpenProfileFromMem(NULL, ...)'),
    )
    seqs = [['cmsOpenProfileFromMem', 'cmsCloseProfile']]
    _, ledger = p.plan(
        seqs, idioms_payload=idioms,
        project_api_names={'cmsOpenProfileFromMem', 'cmsCloseProfile'},
    )
    assert ledger.synthesized_count == 0


def test_synthesize_skipped_when_api_not_in_project():
    p = PathPlanner(project='cjson')
    idioms = _payload(
        _idiom('context_null_pass', 'some_other_lib_api(NULL, ...)'),
    )
    seqs = [['cJSON_Parse']]
    _, ledger = p.plan(
        seqs, idioms_payload=idioms,
        project_api_names={'cJSON_Parse'},  # other_lib_api absent
    )
    assert ledger.synthesized_count == 0


def test_synthesis_respects_max_synth_cap():
    p = PathPlanner(project='lcms')
    idioms = _payload(
        _idiom('context_null_pass', 'cmsA(NULL, ...)'),
        _idiom('context_null_pass', 'cmsB(NULL, ...)'),
        _idiom('context_null_pass', 'cmsC(NULL, ...)'),
        _idiom('context_null_pass', 'cmsD(NULL, ...)'),
    )
    seqs = [['cmsX']]
    project_apis = {'cmsX', 'cmsA', 'cmsB', 'cmsC', 'cmsD'}
    _, ledger = p.plan(seqs, idioms_payload=idioms,
                       project_api_names=project_apis, max_synth=2)
    assert ledger.synthesized_count == 2


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_plan_and_persist_writes_ledger():
    with tempfile.TemporaryDirectory() as td:
        state_dir = Path(td) / 'state'
        _, ledger = plan_and_persist(
            project='cjson',
            target_sequences=[['cJSON_Parse']],
            idioms_payload=_payload(
                _idiom('cleanup_pair', 'cJSON_Parse(...) → cJSON_Delete(...);')),
            project_api_names={'cJSON_Parse', 'cJSON_Delete'},
            state_dir=state_dir,
        )
        out = state_dir / 'plan_ledger.json'
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded['project'] == 'cjson'
        assert loaded['candidate_count_in'] == 1
        assert isinstance(loaded['plans'], list)


def test_plan_ledger_to_dict_shape():
    ledger = PlanLedger(project='p', candidate_count_in=2)
    ledger.add(CandidatePlan(
        sequence_names=['a'],
        origin=CandidateOrigin.L4_RANDOM_WALK,
        score=0.5,
        rationale=['idiom hit'],
        matched_idioms=['cleanup_pair'],
    ))
    d = ledger.to_dict()
    assert d['plans'][0]['origin'] == 'l4_random_walk'
    assert d['plans'][0]['score'] == 0.5
