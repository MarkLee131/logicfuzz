#!/bin/bash -eu

cd $SRC/my-project

# Compile the library with fuzzing instrumentation
$CC $CFLAGS -c strparser.c -o strparser.o

# Create static library
ar rcs libstrparser.a strparser.o

# Create an empty fuzzer placeholder (LogicFuzz will generate actual harness)
cat > $SRC/fuzzer.c << 'EOF'
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // LogicFuzz will replace this with generated fuzzer
    return 0;
}
EOF

# Compile and link the fuzzer
$CC $CFLAGS -I$SRC/my-project -c $SRC/fuzzer.c -o $WORK/fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $WORK/fuzzer.o \
    $SRC/my-project/libstrparser.a \
    -o $OUT/my_project_fuzzer

# Copy necessary files to $OUT for LogicFuzz
cp $SRC/my-project/strparser.h $OUT/
cp $SRC/my-project/strparser.c $OUT/
