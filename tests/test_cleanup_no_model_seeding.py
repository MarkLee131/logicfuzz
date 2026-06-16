"""`_generate_cleanup`'s destroyer reality-gate must be OFF when no model is
present. Bug (2026-06 review): ``_valid_apis`` was seeded from ``seq_api_names``
(the sequence's own APIs), which is non-empty for any real sequence — so the
``_real_destroy`` "empty valid_apis ⇒ keep legacy inference" escape hatch was
DEAD, and a legitimate paired destroyer that isn't itself in the sequence (e.g.
``cJSON_Delete`` for an in-sequence ``cJSON_Parse``) got wrongly SUPPRESSED →
resource leak. The reality-gate exists only to suppress NAME-INVENTED symbols
using the model's authoritative API universe; with no model we cannot validate,
so we must trust the name-pattern inference (compile-validation catches any truly
invalid symbol downstream). Production threads ``dep_model`` (CBFactory), so this
only bit the model-absent helper path — but the docstring promised an escape
hatch that didn't work.
"""
from liberator_adapter.common.api import Api
from liberator_adapter.driver.synthesis.skeleton_generator import (
    SkeletonGenerator, DriverSkeleton, SkeletonVariable,
)


def _api(name):
    return Api(name, False, None, [], [])


def _skeleton(producer, var, ctype, apis):
    sk = DriverSkeleton(name="t", target_apis=[_api(a) for a in apis])
    sk.add_variable(SkeletonVariable(name=var, c_type=ctype,
                                     source_api=producer, is_pointer=True))
    return sk


def _cleanup_text(sk):
    return "\n".join(s.code for s in sk.cleanup_statements)


class _Model:
    def __init__(self, names):
        self.apis = {n: None for n in names}


def test_no_model_does_not_suppress_real_destroyer():
    # dep_model=None: cJSON_Delete is a real pair for cJSON_Parse but is NOT in
    # the sequence; without a model the gate must NOT suppress it.
    gen = SkeletonGenerator()
    sk = _skeleton("cJSON_Parse", "j", "cJSON*", ["cJSON_Parse"])
    gen._generate_cleanup(sk, dep_model=None)
    assert "cJSON_Delete(j)" in _cleanup_text(sk)


def test_model_present_keeps_real_destroyer():
    # With a model that contains the destroyer, it is emitted (gate passes).
    gen = SkeletonGenerator()
    sk = _skeleton("cJSON_Parse", "j", "cJSON*", ["cJSON_Parse"])
    gen._generate_cleanup(sk, dep_model=_Model(["cJSON_Parse", "cJSON_Delete"]))
    assert "cJSON_Delete(j)" in _cleanup_text(sk)


def test_model_present_suppresses_hallucinated_destroyer():
    # With a model, an INVENTED symbol (cmsCreateContext → 'cmsDestroy', not a
    # real API) is still suppressed — the reality-gate stays active when armed.
    gen = SkeletonGenerator()
    sk = _skeleton("cmsCreateContext", "ctx", "cmsContext", ["cmsCreateContext"])
    gen._generate_cleanup(sk, dep_model=_Model(["cmsCreateContext", "cmsDeleteContext"]))
    assert "cmsDestroy" not in _cleanup_text(sk)
