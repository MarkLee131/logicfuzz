"""RESIDUAL_ALLCOVER must NOT emit destroyer/free-family APIs as single-API
residuals: a standalone free/destroy renders its freed pointer arg as a stack
buffer → cJSON_free(stackbuf) → invalid-free crash (cjson: 2 such residuals =
~9.6k crashes dominating the merged harness). Chainable destroyers are already
in constructed creator→…→destroyer sequences (covered), so the residual ones are
exactly the unchainable stack-free crashers."""
from src.context.data_context import _residual_allcover_apis


class _Api:
    def __init__(self, n): self.function_name = n


def _names(apis): return {a.function_name for a in apis}


def test_excludes_destroyer_family():
    apis = [_Api('cJSON_Parse'), _Api('cJSON_free'), _Api('cJSON_Delete'),
            _Api('cJSON_Print')]
    res = _residual_allcover_apis(apis, covered_names=set(),
                                  destroyer_names={'cJSON_free', 'cJSON_Delete'})
    assert _names(res) == {'cJSON_Parse', 'cJSON_Print'}


def test_excludes_already_covered_and_underscore():
    apis = [_Api('cJSON_Parse'), _Api('cJSON_GetArrayItem'), _Api('_internal')]
    res = _residual_allcover_apis(apis, covered_names={'cJSON_Parse'},
                                  destroyer_names=set())
    assert _names(res) == {'cJSON_GetArrayItem'}


def test_no_model_fails_open_keeps_non_destroyers():
    apis = [_Api('cJSON_Parse'), _Api('cJSON_Print')]
    res = _residual_allcover_apis(apis, covered_names=set(), destroyer_names=None)
    assert _names(res) == {'cJSON_Parse', 'cJSON_Print'}
