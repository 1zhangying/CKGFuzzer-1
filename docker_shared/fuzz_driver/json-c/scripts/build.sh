#!/bin/bash -eu

cd "$SRC/json-c"

mkdir -p build
cd build
cmake \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DDISABLE_WERROR=ON \
  -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY="$PWD/libout" \
  ..
make -j$(nproc)

$CXX $CXXFLAGS -std=c++17 \
  -I"$SRC/json-c" \
  -I"$SRC/json-c/build" \
  -c "$SRC/json-c/test/FUZZ_DRIVER_FILE" \
  -o "$WORK/FUZZ_DRIVER_FILE_TARGET.o"

$CXX $CXXFLAGS -std=c++17 "$WORK/FUZZ_DRIVER_FILE_TARGET.o" \
  -o "$OUT/FUZZ_DRIVER_FILE_TARGET" \
  $LIB_FUZZING_ENGINE "$SRC/json-c/build/libout/libjson-c.a" \
  -lm
