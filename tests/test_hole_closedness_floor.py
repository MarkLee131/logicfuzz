"""Root cause (closedness, I1): _merge_holes_into_skeleton only floored __INIT_→0;
ARRAY_LENGTH and REFINE had no fallback, so on the empty-dict B-design floor path
(or any omitted LLM key) the raw macro leaked into the final C → "use of undeclared
identifier '__ARRLEN_arrlen_1__' / '__REFINE_src0__'" (11 cjson/zlib leaks). A sketch
is a program only once every hole is bound (template-synthesis closedness): the
substitution map must be TOTAL over the placeholder domain. _floor_unfilled_holes
grounds EVERY residual hole-kind placeholder."""
import re
try:
    from src.agents.prototyper import LangGraphPrototyper  # noqa
except ImportError:
    from src.agents.prototyper import LangGraphPrototyper  # noqa

_FLOOR = LangGraphPrototyper._floor_unfilled_holes
_HOLE_RE = r'__(?:HOLE|BUFSIZE|CALLBACK|INIT|LOOPCOND|LOOPBOUND|CLEANUP|ARRLEN|ERRHANDLE|COMPLEX_HOLE|REFINE)_[\w]+__'


def test_no_placeholder_survives():
    code = ('uint8_t a[__ARRLEN_arrlen_1__];\n'
            'int b = __REFINE_src0__;\n'
            'int c = __INIT_cfg__;\n'
            'size_t n = __BUFSIZE_len__;\n')
    out = _FLOOR(code)
    assert not re.search(_HOLE_RE, out), out


def test_arrlen_floors_to_bounded_size():
    assert _FLOOR('uint8_t a[__ARRLEN_arrlen_1__]') == 'uint8_t a[64]'


def test_others_floor_to_zero():
    assert _FLOOR('x = __REFINE_src0__') == 'x = 0'
    assert _FLOOR('y = __INIT_k__') == 'y = 0'


def test_real_code_unchanged():
    code = 'int main(void) { return 0; }'
    assert _FLOOR(code) == code
