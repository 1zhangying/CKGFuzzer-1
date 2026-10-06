#!/bin/bash -eu

cd "$SRC/expat"

mkdir -p build
cd build
cmake \
  -DEXPAT_BUILD_DOCS=OFF \
  -DEXPAT_BUILD_EXAMPLES=OFF \
  -DEXPAT_BUILD_TESTS=OFF \
  -DEXPAT_BUILD_TOOLS=OFF \
  -DEXPAT_SHARED_LIBS=OFF \
  -DEXPAT_WITH_LIBBSD=OFF \
  -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY="$PWD/libout" \
  ../expat
make -j$(nproc)

$CXX $CXXFLAGS -std=c++11 \
  -I"$SRC/expat/expat/lib" \
  -I"$SRC/expat/build" \
  -c "$SRC/expat/test/FUZZ_DRIVER_FILE" \
  -o "$WORK/FUZZ_DRIVER_FILE_TARGET.o"

$CXX $CXXFLAGS -std=c++11 "$WORK/FUZZ_DRIVER_FILE_TARGET.o" \
  -o "$OUT/FUZZ_DRIVER_FILE_TARGET" \
  $LIB_FUZZING_ENGINE "$SRC/expat/build/libout/libexpat.a"
