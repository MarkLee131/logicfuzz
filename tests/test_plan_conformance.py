"""Precision pin for the plan-conformance check (architecture-cleanup #4 guard).

The check must (a) PASS validated-good LLM drivers — including ones that
legitimately DROP incoherent planned APIs (write-side setters, deprecated
re-initializers) — and (b) CATCH the A-design failure mode: shallow drivers that
lost the deep chain, and parser-entry reverts that swap the planned lifecycle for
a one-shot not in the plan. It must not be fooled by API names in comments.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from liberator_adapter.analysis.plan_conformance import analyze_conformance  # noqa: E402

# A libpng read plan (creator → info → read_info → transforms → terminal decode → destroy)
PLAN = [
    "png_create_read_struct", "png_create_info_struct", "png_info_init_3",
    "png_set_user_limits", "png_read_info", "png_set_swap",
    "png_set_tRNS_to_alpha", "png_start_read_image", "png_read_image",
]
DESTROYERS = ["png_destroy_read_struct"]
TERMINALS = ["png_read_image", "png_read_png"]

# --- fixtures ---------------------------------------------------------------

GOOD_DEEP = """
int LLVMFuzzerTestOneInput_3(const uint8_t *d, size_t n){
  png_structp p = png_create_read_struct(PNG_LIBPNG_VER_STRING,0,0,0);
  png_infop i = png_create_info_struct(p);
  png_set_user_limits(p, 16384, 16384);
  png_set_read_fn(p, &src, FuzzReadFn);
  png_read_info(p, i);
  png_set_swap(p); png_set_tRNS_to_alpha(p);
  png_start_read_image(p);
  png_uint_32 h = png_get_image_height(p,i);
  png_bytep* rows = (png_bytep*)calloc(h, sizeof(png_bytep));
  png_read_image(p, rows);            /* terminal decode */
  png_destroy_read_struct(&p,&i,0);
  return 0;
}
"""

# Legitimately drops png_info_init_3 (deprecated) + two setters — backbone intact.
GOOD_WITH_DROPS = """
int LLVMFuzzerTestOneInput_5(const uint8_t *d, size_t n){
  png_structp p = png_create_read_struct(PNG_LIBPNG_VER_STRING,0,0,0);
  png_infop i = png_create_info_struct(p);
  png_set_read_fn(p, &src, FuzzReadFn);
  png_read_info(p, i);
  png_read_image(p, rows);            /* terminal decode kept */
  png_destroy_read_struct(&p,&i,0);
  return 0;
}
"""

# A-design failure 1: shallow — created the handle then bailed. No terminal.
SHALLOW = """
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){
  png_structp p = png_create_read_struct(PNG_LIBPNG_VER_STRING,0,0,0);
  png_infop i = png_create_info_struct(p);
  png_destroy_read_struct(&p,&i,0);
  return 0;
}
"""

# A-design failure 2: parser-revert — swapped the planned chain for a one-shot
# NOT in the plan; the planned terminal png_read_image is never called.
PARSER_REVERT = """
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){
  png_image image; memset(&image,0,sizeof image);
  image.version = PNG_IMAGE_VERSION;
  png_image_begin_read_from_memory(&image, d, n);   /* one-shot, not planned */
  png_image_finish_read(&image, 0, buf, 0, 0);
  return 0;
}
"""

# An API named only in a COMMENT must not count as a call.
COMMENT_ONLY_TERMINAL = """
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){
  png_structp p = png_create_read_struct(PNG_LIBPNG_VER_STRING,0,0,0);
  png_infop i = png_create_info_struct(p);
  png_read_info(p, i);
  // NOTE: png_read_image(p, rows) is intentionally skipped here.
  png_destroy_read_struct(&p,&i,0);
  return 0;
}
"""


def _c(src):
    return analyze_conformance(PLAN, src, destroyers=DESTROYERS, terminals=TERMINALS)


def test_good_deep_driver_conforms():
    r = _c(GOOD_DEEP)
    assert r.conformant, r.reasons
    assert r.has_creator and r.has_terminal


def test_good_driver_with_legitimate_drops_conforms():
    r = _c(GOOD_WITH_DROPS)
    assert r.conformant, r.reasons          # backbone intact despite 44% kept (advisory only)
    assert r.has_terminal


def test_shallow_driver_rejected():
    r = _c(SHALLOW)
    assert not r.conformant
    assert not r.has_terminal                # the depth signal that catches it


def test_parser_revert_rejected():
    r = _c(PARSER_REVERT)
    assert not r.conformant
    assert not r.has_terminal                # planned terminal never called


def test_comment_mention_not_counted_as_call():
    r = _c(COMMENT_ONLY_TERMINAL)
    assert "png_read_image" not in r.called  # comment-stripped
    assert not r.conformant                  # so it's correctly flagged shallow


def test_role_inference_without_hints():
    # No explicit role hints: terminals inferred from plan order + naming.
    r = analyze_conformance(PLAN, GOOD_DEEP)
    assert r.conformant, r.reasons
    r2 = analyze_conformance(PLAN, SHALLOW)
    assert not r2.conformant
