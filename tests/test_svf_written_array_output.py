"""SVF write+array → OUTPUT promotion (libpng png_build_grayscale_palette).

A value-struct pointer (``png_color *palette``) is type-classified as a handle →
HANDLE_IN default. But SVF proved it ``write`` + ``is_array`` — that is an OUTPUT
buffer, not an in-out handle. The reconcile's write→OUTPUT promotion was gated to
CONFIG only (to protect commonly-in-out HANDLE_INs); the ``is_array`` signal is the
discriminator: a written ARRAY is an output buffer (an in-out handle is a single
struct, is_array=False). Threading ``_svf_is_array`` + promoting HANDLE_IN→OUTPUT
when written AND is_array fixes the misclassification without touching in-out
handles.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from liberator_adapter.analysis.api_semantic_model import (  # noqa: E402
    ArgRole, reconcile,
)
from liberator_adapter.analysis import usedef  # noqa: E402


def _api(name, args, ret="void"):
    return {"function_name": name, "arguments": args, "return_type": ret,
            "is_vararg": False, "namespace": []}


def _arg(type_str, **svf):
    a = {"type": type_str, "is_const": [False], "name": svf.pop("name", "")}
    a.update(svf)
    return a


def test_written_array_handle_promoted_to_output():
    api = _api("png_build_grayscale_palette", [
        _arg("int", name="bit_depth"),
        _arg("png_color *", name="palette", _svf_writes=True, _svf_is_array=True),
    ])
    sem = reconcile([api]).get("png_build_grayscale_palette")
    assert sem.args[1].role is ArgRole.OUTPUT, sem.args[1].role


def test_inout_handle_not_promoted():
    # written but NON-array (a single in-out handle) stays a handle, never OUTPUT.
    api = _api("png_set_x", [
        _arg("png_struct *", name="png_ptr", _svf_writes=True, _svf_is_array=False),
    ])
    sem = reconcile([api]).get("png_set_x")
    assert sem.args[0].role is not ArgRole.OUTPUT, sem.args[0].role


def test_annotate_threads_is_array():
    apis = [{"function_name": "f",
             "arguments": [{"type": "png_color *", "name": "p"}]}]
    conditions = [{
        "function_name": "f",
        "param_0": {"access_type_set": [{"access": "write", "fields": [0]}],
                    "is_array": True},
    }]
    usedef.annotate_svf_writes(apis, conditions)
    assert apis[0]["arguments"][0].get("_svf_is_array") is True
    assert apis[0]["arguments"][0].get("_svf_writes") is True
