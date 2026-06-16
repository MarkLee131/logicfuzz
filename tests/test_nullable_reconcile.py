"""§3.0 reconcile: ArgSemantics.nullable from evidence, priority IR > doc > role.
Makes the Validity Contract's nullable signal evidence-based, not a role guess."""
from liberator_adapter.analysis.api_semantic_model import _reconcile_arg_nullable


def test_doc_nullable_overrides_role():
    # role default says non-null (handle), doc says may-be-NULL -> nullable True
    assert _reconcile_arg_nullable(role_default=False, doc=True, ir_nonnull=None) is True


def test_doc_nonnull_overrides_role_nullable():
    assert _reconcile_arg_nullable(role_default=True, doc=False, ir_nonnull=None) is False


def test_ir_nonnull_wins_over_doc_silence():
    assert _reconcile_arg_nullable(role_default=True, doc=None, ir_nonnull=True) is False


def test_ir_nonnull_wins_over_doc_nullable():
    # IR proof of deref/assert beats a vague doc cue
    assert _reconcile_arg_nullable(role_default=True, doc=True, ir_nonnull=True) is False


def test_role_fallback_when_no_evidence():
    assert _reconcile_arg_nullable(role_default=False, doc=None, ir_nonnull=None) is False
    assert _reconcile_arg_nullable(role_default=True, doc=None, ir_nonnull=None) is True
