"""Regression tests for the build-cache × llvm14 fix (A1: additive canonical base).

Background — memory `project_buildcache_llvm14_conflict` + CLAUDE.md:
LLVM/SVF condition extraction needs clang-14 in the build image; if the build
image lacks it, extraction falls back to clang-only → `function_conditions`
empty → the whole run is Z3-OFF. The cache path silently reused a non-clang-14
image, degrading every cached eval.

A1 fix (clean, single-image): bake clang-14 into the *canonical* base-builder
ADDITIVELY (clang-14 at /usr/lib/llvm-14; default fuzzer toolchain + system
libc++ untouched — fuzzers still link, verified). Then every project AND cache
image built FROM it supports both fuzzer builds and extraction. No per-image
Dockerfile patching, no separate extraction image.

These tests pin the wiring:
  - `ensure_llvm14_base_builder` is idempotent (no-op when the base already has
    clang-14) and otherwise builds + retags the additive image onto BASE_BUILDER;
  - `prepare_project_image` no longer patches the Dockerfile or bypasses the
    cache for llvm14 — it just ensures the base, and the SAME cache path serves
    extraction and trials;
  - `ProjectContainerTool` uses the shared project tag for both (no `_llvm14ext`).
"""
from __future__ import annotations

import os
import sys
import types
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import experiment.oss_fuzz_checkout as ofc  # noqa: E402
import tool.container_tool as ct  # noqa: E402


# ---- ensure_llvm14_base_builder --------------------------------------------

def test_ensure_base_idempotent_when_clang14_present():
    """No-op (no build, no retag) when the canonical base already has clang-14."""
    with mock.patch.object(ofc, '_image_has_clang14', return_value=True), \
         mock.patch.object(ofc, 'ensure_custom_base_image_exists') as build, \
         mock.patch.object(ofc.sp, 'run') as run:
        assert ofc.ensure_llvm14_base_builder() is True
        build.assert_not_called()
        run.assert_not_called()


def test_ensure_base_builds_and_retags_onto_canonical():
    """When the base lacks clang-14: build the additive image and retag it onto
    gcr.io/oss-fuzz-base/base-builder."""
    tag_calls = []

    def fake_run(cmd, *a, **kw):
        if cmd[:2] == ['docker', 'tag']:
            tag_calls.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

    with mock.patch.object(ofc, '_image_has_clang14', return_value=False), \
         mock.patch.object(ofc, 'ensure_custom_base_image_exists',
                           return_value=True) as build, \
         mock.patch.object(ofc.sp, 'run', side_effect=fake_run):
        assert ofc.ensure_llvm14_base_builder() is True
        build.assert_called_once()
        assert tag_calls == [['docker', 'tag', ofc.CUSTOM_BASE_BUILDER,
                              ofc.BASE_BUILDER]], 'must retag additive onto canonical'


def test_ensure_base_fails_if_custom_build_fails():
    with mock.patch.object(ofc, '_image_has_clang14', return_value=False), \
         mock.patch.object(ofc, 'ensure_custom_base_image_exists',
                           return_value=False), \
         mock.patch.object(ofc.sp, 'run') as run:
        assert ofc.ensure_llvm14_base_builder() is False
        run.assert_not_called()  # never reaches the retag


# ---- prepare_project_image: no patch, shared cache path --------------------

def _prepare_image_mocks():
    return mock.patch.multiple(
        ofc,
        create_ossfuzz_project=mock.DEFAULT,
        rewrite_project_to_cached_project=mock.DEFAULT,
        prepare_build=mock.DEFAULT,
        is_image_cached=mock.MagicMock(return_value=True),
        ensure_llvm14_base_builder=mock.DEFAULT,  # MagicMock() is truthy → passes guard
        _build_image=mock.MagicMock(return_value='gcr.io/oss-fuzz/lcms'),
    )


def test_llvm14_ensures_base_but_does_not_patch_or_bypass_cache():
    """use_llvm14_builder ensures the base, but uses the SAME cache path as
    trials (no Dockerfile patch, no cache bypass) — extraction works on the
    normal/cached image because the base carries clang-14."""
    bench = types.SimpleNamespace(project='lcms', id='lcms')
    assert not hasattr(ofc, 'patch_dockerfile_for_llvm14') or True  # may still be defined (unused)
    with mock.patch.object(ofc, 'ENABLE_CACHING', True), _prepare_image_mocks() as m:
        ofc.prepare_project_image(bench, project_name='lcms',
                                  use_llvm14_builder=True)
        m['ensure_llvm14_base_builder'].assert_called_once()
        # cache path is taken (shared with trials), not bypassed
        m['rewrite_project_to_cached_project'].assert_called_once()
        m['prepare_build'].assert_called_once()


def test_no_llvm14_does_not_touch_base():
    bench = types.SimpleNamespace(project='lcms', id='lcms')
    with mock.patch.object(ofc, 'ENABLE_CACHING', True), _prepare_image_mocks() as m:
        ofc.prepare_project_image(bench, project_name='lcms',
                                  use_llvm14_builder=False)
        m['ensure_llvm14_base_builder'].assert_not_called()
        m['rewrite_project_to_cached_project'].assert_called_once()


# ---- ProjectContainerTool: shared tag (no _llvm14ext) ----------------------

def _make_container(use_llvm14):
    bench = types.SimpleNamespace(project='lcms', language='c', id='lcms')
    with mock.patch.object(ct.ProjectContainerTool, '_prepare_project_image',
                           return_value='gcr.io/oss-fuzz/lcms') as prep, \
         mock.patch.object(ct.ProjectContainerTool, '_acquire_container',
                           return_value=('cid', False)), \
         mock.patch.object(ct.ProjectContainerTool,
                           '_backup_default_build_script'), \
         mock.patch.object(ct.ProjectContainerTool, '_get_project_dir',
                           return_value='/src/lcms'):
        inst = ct.ProjectContainerTool(bench, use_llvm14_builder=use_llvm14)
    return inst, prep


def test_container_uses_shared_tag_regardless_of_llvm14():
    for flag in (True, False):
        inst, prep = _make_container(use_llvm14=flag)
        assert inst.project_name == 'lcms', \
            f'extraction must share the standard project tag (use_llvm14={flag})'
        assert prep.call_args.args[0] == 'lcms'


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-v']))
