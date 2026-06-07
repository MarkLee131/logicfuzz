# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unit tests for the library build-cache reduced-build-script transform
(``LOGICFUZZ_LIB_CACHE``). Pure-function tests — no Docker, no IO.

Covers the core invariant behind the per-trial speedup: a project ``build.sh``
that does ``./configure && make`` for the library and then compiles the fuzzer
with ``$CC ... $OUT`` is reduced so the library-build commands are stripped but
the fuzzer compile/link and asset copies are preserved.
"""
import unittest

from experiment.oss_fuzz_checkout import derive_library_cached_build_script


# The real lcms OSS-Fuzz build.sh shape: configure + make all (library), then a
# per-fuzzer $CC/$CXX compile-and-link loop against the static .a.
_LCMS_BUILD_SH = """#!/bin/bash -eu
# build the target.
./configure --enable-shared=no
make -j$(nproc) all

FUZZERS="cms_transform_fuzzer cms_profile_fuzzer"
for F in $FUZZERS; do
    $CC $CFLAGS -c -Iinclude $SRC/$F.c -o $SRC/$F.o
    $CXX $CXXFLAGS $SRC/$F.o -o $OUT/$F $LIB_FUZZING_ENGINE src/.libs/liblcms2.a
done
cp $SRC/*.dict $OUT/
"""


class DeriveLibraryCachedBuildScriptTest(unittest.TestCase):
  """Tests for derive_library_cached_build_script."""

  def test_strips_configure_and_make(self):
    reduced = derive_library_cached_build_script(_LCMS_BUILD_SH)
    self.assertIsNotNone(reduced)
    self.assertIn('# [libcache-skipped] ./configure --enable-shared=no', reduced)
    self.assertIn('# [libcache-skipped] make -j$(nproc) all', reduced)

  def test_keeps_fuzzer_compile_and_link(self):
    reduced = derive_library_cached_build_script(_LCMS_BUILD_SH)
    # The fuzzer compile/link loop and asset copy must survive un-commented.
    self.assertIn('$CC $CFLAGS -c -Iinclude $SRC/$F.c -o $SRC/$F.o', reduced)
    self.assertIn('-o $OUT/$F $LIB_FUZZING_ENGINE src/.libs/liblcms2.a', reduced)
    self.assertIn('cp $SRC/*.dict $OUT/', reduced)
    # The kept lines are NOT prefixed with the skip marker.
    for line in reduced.split('\n'):
      if 'liblcms2.a' in line or 'cp $SRC/*.dict' in line:
        self.assertFalse(line.lstrip().startswith('#'),
                         f'fuzzer line wrongly stripped: {line!r}')

  def test_reduced_script_has_shebang(self):
    reduced = derive_library_cached_build_script(_LCMS_BUILD_SH)
    self.assertTrue(reduced.startswith('#!/bin/bash -eu'))
    # No duplicate shebang carried over from the original.
    self.assertEqual(reduced.count('#!/bin/bash'), 1)

  def test_make_fuzzers_line_is_kept(self):
    # ``make`` lines that build the fuzzer (contain 'fuzz') must NOT be stripped.
    script = ('./configure\n'
              'make -j$(nproc)\n'
              'make fuzzers\n'
              '$CXX o.o -o $OUT/x $LIB_FUZZING_ENGINE lib.a\n')
    reduced = derive_library_cached_build_script(script)
    self.assertIsNotNone(reduced)
    self.assertIn('# [libcache-skipped] make -j$(nproc)', reduced)
    # 'make fuzzers' kept intact.
    self.assertIn('\nmake fuzzers\n', reduced)

  def test_multiline_continuation_stripped_as_unit(self):
    script = ('cmake -DFOO=1 \\\n'
              '      -DBAR=2 ..\n'
              'make\n'
              '$CC f.c -o $OUT/f $LIB_FUZZING_ENGINE lib.a\n')
    reduced = derive_library_cached_build_script(script)
    self.assertIsNotNone(reduced)
    self.assertIn('# [libcache-skipped] cmake -DFOO=1 \\', reduced)
    self.assertIn('# [libcache-skipped]       -DBAR=2 ..', reduced)

  def test_returns_none_when_no_out_compile(self):
    # Fuzzer built only via make -> cannot safely strip the library build.
    self.assertIsNone(derive_library_cached_build_script('make -j fuzzers\n'))

  def test_returns_none_when_no_library_commands(self):
    # Nothing to strip -> no benefit, fall back to full build.
    self.assertIsNone(
        derive_library_cached_build_script(
            '$CC foo.c -o $OUT/x $LIB_FUZZING_ENGINE lib.a\n'))

  def test_returns_none_on_empty(self):
    self.assertIsNone(derive_library_cached_build_script(''))
    self.assertIsNone(derive_library_cached_build_script('   \n  '))


if __name__ == '__main__':
  unittest.main()
