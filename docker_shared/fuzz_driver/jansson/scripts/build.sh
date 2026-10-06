#!/bin/bash -eu

cd "$SRC/jansson"

mkdir -p build
cd build
cmake \
  -DBUILD_SHARED_LIBS=OFF \
  -DJANSSON_BUILD_DOCS=OFF \
  -DJANSSON_BUILD_MAN=OFF \
  -DJANSSON_EXAMPLES=OFF \
  -DWITHOUT_TESTS=ON \
  ..
make -j$(nproc)

$CXX $CXXFLAGS -std=c++11 \
  -I"$SRC/jansson/src" \
  -I"$SRC/jansson/build/include" \
  -c "$SRC/jansson/test/FUZZ_DRIVER_FILE" \
  -o "$WORK/FUZZ_DRIVER_FILE_TARGET.o"

$CXX $CXXFLAGS -std=c++11 "$WORK/FUZZ_DRIVER_FILE_TARGET.o" \
  -o "$OUT/FUZZ_DRIVER_FILE_TARGET" \
  $LIB_FUZZING_ENGINE "$SRC/jansson/build/lib/libjansson.a"
