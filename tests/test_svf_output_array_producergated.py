"""Producer-gated SVF write+array → OUTPUT promotion (sound version).

A param the IR type-classes as a handle but that SVF proved is a WRITTEN ARRAY is
an OUTPUT value-array ONLY IF its element type has no producer in the project.
Two gates are jointly necessary:
  - is_array=True excludes a single in-out handle (is_array=False);
  - element-type-not-produced excludes a managed handle that is merely
    array-accessed (cJSON's linked nodes, gzFile — both HAVE a creator).

png_color (palette) has no creator and is_array=True → OUTPUT.
cJSON (cJSON_DetachItemViaPointer item) HAS a creator (cJSON_Create*) → stays
HANDLE_IN. This is the regression an is_array-only rule introduced (now avoided).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from liberator_adapter.analysis.api_semantic_model import ArgRole, reconcile  # noqa: E402


def _api(name, args, ret="void"):
    return {"function_name": name, "arguments": args, "return_type": ret,
            "is_vararg": False, "namespace": []}


def _arg(type_str, **svf):
    a = {"type": type_str, "is_const": [False], "name": svf.pop("name", "")}
    a.update(svf)
    return a


def test_producerless_written_array_promoted():
    # png_color is never produced by any API -> value array -> OUTPUT.
    api = _api("png_build_grayscale_palette", [
        _arg("int", name="bit_depth"),
        _arg("png_color *", name="palette", _svf_writes=True, _svf_is_array=True),
    ])
    sem = reconcile([api]).get("png_build_grayscale_palette")
    assert sem.args[1].role is ArgRole.OUTPUT, sem.args[1].role


def test_produced_handle_array_NOT_promoted():
    # cJSON HAS a creator in the project -> a managed handle, never OUTPUT, even
    # though SVF marked the detached item write+is_array.
    api_create = _api("cJSON_CreateObject", [], ret="cJSON *")  # producer of cJSON
    api_detach = _api("cJSON_DetachItemViaPointer", [
        _arg("cJSON *", name="parent", _svf_writes=True, _svf_is_array=False),
        _arg("cJSON *", name="item", _svf_writes=True, _svf_is_array=True),
    ], ret="cJSON *")
    m = reconcile([api_create, api_detach])
    item = m.get("cJSON_DetachItemViaPointer").args[1]
    assert item.role is ArgRole.HANDLE_IN, item.role


def test_inout_handle_not_promoted():
    # written but NON-array (single in-out handle) is never OUTPUT.
    api = _api("png_set_x", [
        _arg("png_struct *", name="p", _svf_writes=True, _svf_is_array=False),
    ])
    sem = reconcile([api]).get("png_set_x")
    assert sem.args[0].role is not ArgRole.OUTPUT, sem.args[0].role
