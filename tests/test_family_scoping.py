"""BREAKING over-fit #2: validity_contract._family substring-matched an lcms family
allow-list, so non-lcms types/names sharing a substring spuriously matched
(EVP_PIPELINE→pipeline, png_context→context, GLTFStage→stage, it8_data→it8) →
CBFactory.produced_by_family cross-wired two UNRELATED handle types. Scope the
allow-list to lcms-style strings (must contain 'cms'); non-lcms → None → falls to
the type-exact binding (which #1 restored)."""
from liberator_adapter.analysis.validity_contract import _family


def test_lcms_families_unchanged():
    assert _family("cmsHPROFILE") == "profile"
    assert _family("cmsHTRANSFORM") == "transform"
    assert _family("cmsCreateTransform") == "transform"   # producer NAME
    assert _family("cmsPipeline *") == "pipeline"
    assert _family("cmsStage *") == "stage"


def test_non_lcms_substring_no_spurious_family():
    assert _family("EVP_PIPELINE_st") is None     # was "pipeline"
    assert _family("png_context") is None          # was "context"
    assert _family("GLTFStage") is None            # was "stage"
    assert _family("struct it8_data *") is None     # was "it8"
    assert _family("my_transform_t") is None        # was "transform"
    assert _family("png_struct *") is None
