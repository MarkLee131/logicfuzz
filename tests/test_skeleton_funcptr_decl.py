"""Root cause (def-use, I2): SkeletonVariable.get_declaration emitted `{c_type} {name}`,
which is malformed C for a function-pointer c_type — `int (*)(args) name` instead of
`int (*name)(args)`. The decl is rejected but the name is still USED in the call →
"use of undeclared identifier 'arg1_inflateBack'" (8 zlib inflateBack leaks). Fix:
splice the identifier into the `(*)` declarator slot (named-declarator formatting)."""
from liberator_adapter.driver.synthesis.skeleton_generator import SkeletonVariable


def test_function_pointer_decl_splices_name():
    v = SkeletonVariable(name='arg1_inflateBack',
                         c_type='unsigned int (*)(void *, unsigned char **)',
                         init_value='NULL')
    d = v.get_declaration()
    assert '(*arg1_inflateBack)' in d, d          # name spliced INSIDE (*...)
    assert '(*) arg1_inflateBack' not in d         # NOT the malformed appended form
    assert d.endswith('= NULL'), d


def test_scalar_decl_unchanged():
    assert SkeletonVariable(name='x', c_type='int', init_value='0').get_declaration() == 'int x = 0'


def test_pointer_decl_unchanged():
    assert SkeletonVariable(name='p', c_type='char *', init_value='NULL').get_declaration() == 'char * p = NULL'


def test_array_decl_unchanged():
    v = SkeletonVariable(name='buf', c_type='uint8_t', is_array=True, array_size='64', init_value='{0}')
    assert v.get_declaration() == 'uint8_t buf[64] = {0}'
