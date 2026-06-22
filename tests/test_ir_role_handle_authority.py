"""Systematic role classification — per-facet authority (TYPE owns handle-ness).
The IR role lattice must treat a pointer-WRITE as handle production ONLY when the
written thing is a HANDLE type. png_read_image writes png_byte* (a buffer) and is
flagged a ConditionManager 'source', but creates no handle → it must be CONSUMER,
not CREATOR. Genuine in-place creators (deflateInit_ writes z_stream, a handle)
stay CREATOR. produces_h/requires_h are already handle-filtered by the caller."""
from liberator_adapter.analysis.api_semantic_model import _classify_ir_role, APIRole


def role(prod_h, req_h, kills=frozenset(), sink=False, src=False, init=False):
    return _classify_ir_role(frozenset(prod_h), frozenset(req_h), frozenset(kills),
                             sink, src, init)[0]


def test_nonhandle_writer_in_sources_is_consumer():
    # png_read_image: produces_h=∅ (png_byte* filtered out), requires a handle, in sources
    assert role(set(), {'png_struct*'}, src=True) is APIRole.CONSUMER


def test_inplace_handle_creator_kept():
    # deflateInit_: produces a handle (z_stream), requires none, source/init
    assert role({'z_stream*'}, set(), src=True, init=True) is APIRole.CREATOR


def test_returned_handle_is_creator():
    assert role({'png_info*'}, set()) is APIRole.CREATOR


def test_handle_in_and_out_is_mutator():
    assert role({'png_info*'}, {'png_info*'}) is APIRole.MUTATOR


def test_consumer_requires_only():
    assert role(set(), {'png_struct*'}) is APIRole.CONSUMER


def test_destroyer_on_kill():
    assert role(set(), {'z_stream*'}, kills={'z_stream*'}) is APIRole.DESTROYER


# --- handle predicate (_compute_handle_types) ---
from types import SimpleNamespace
from liberator_adapter.analysis.api_semantic_model import _compute_handle_types


def _eff(name, kill=(), def_=(), use=()):
    return SimpleNamespace(name=name, kill=set(kill), def_=set(def_), use=set(use))


def test_handle_types_combines_freed_and_created_consumed():
    apis = [
        {'function_name': 'make_z', 'arguments': []},               # creator-named, produces z
        {'function_name': 'use_z',  'arguments': [{'type': 'z *'}]},  # consumes z as HANDLE_IN
        {'function_name': 'free_x', 'arguments': [{'type': 'x *'}]},  # frees x
        {'function_name': 'get_y',  'arguments': []},               # produces non-handle y, never freed/consumed
    ]
    eff = {
        'make_z': _eff('make_z', def_={'z*'}),
        'use_z':  _eff('use_z',  use={'z*'}),
        'free_x': _eff('free_x', kill={'x*'}, use={'x*'}),
        'get_y':  _eff('get_y',  def_={'y*'}),
    }
    h = _compute_handle_types(apis, eff)
    assert 'x*' in h          # freed → handle
    assert 'z*' in h          # created-by-named + consumed-as-handle → handle (the z_stream case)
    assert 'y*' not in h      # produced by a non-creator, never freed/consumed → NOT a handle
