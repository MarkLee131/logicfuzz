"""§3.0 cue 1: mine @param text for nullability — currently the param text is
extracted but only used for value ranges, never for "must not be NULL" /
"may be NULL". `_param_nullability_from_text` returns False (non-NULL), True
(may be NULL), or None (unknown). Nullable cue wins ties (don't over-constrain)."""
from src.knowledge.project_docs import _param_nullability_from_text


def test_must_not_be_null():
    assert _param_nullability_from_text("the profile handle; must not be NULL") is False


def test_nonnull_word():
    assert _param_nullability_from_text("a non-null pointer to the context") is False


def test_may_be_null():
    assert _param_nullability_from_text("context, or NULL for the global context") is True


def test_optional():
    assert _param_nullability_from_text("optional output buffer") is True


def test_unknown_returns_none():
    assert _param_nullability_from_text("the number of channels") is None


def test_empty_returns_none():
    assert _param_nullability_from_text("") is None
    assert _param_nullability_from_text(None) is None
