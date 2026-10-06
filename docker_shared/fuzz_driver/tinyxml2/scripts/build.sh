#!/bin/bash -eu

cd "$SRC/tinyxml2"

TINYXML2_DEBUG_FLAGS=()
CMAKE_EXTRA_ARGS=()
if [ "${FUZZ_TARGET:-}" = "tinyxml2_fuzz_driver_False_qwen3-coder-plus_22" ] || \
   [ "${CRASHSAGE_TINYXML2_DEBUG:-}" = "1" ]; then
  TINYXML2_DEBUG_FLAGS=(-DTINYXML2_DEBUG)
  CMAKE_EXTRA_ARGS=(-DCMAKE_CXX_FLAGS="${CXXFLAGS:-} ${TINYXML2_DEBUG_FLAGS[*]}")
fi

mkdir -p build
cd build
cmake \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DBUILD_TESTS=OFF \
  -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY="$PWD/libout" \
  "${CMAKE_EXTRA_ARGS[@]}" \
  ..
make -j$(nproc)

$CXX $CXXFLAGS -std=c++11 \
  "${TINYXML2_DEBUG_FLAGS[@]}" \
  -I"$SRC/tinyxml2" \
  -I"$SRC/tinyxml2/build" \
  -c "$SRC/tinyxml2/test/FUZZ_DRIVER_FILE" \
  -o "$WORK/FUZZ_DRIVER_FILE_TARGET.o"

$CXX $CXXFLAGS -std=c++11 "$WORK/FUZZ_DRIVER_FILE_TARGET.o" \
  -o "$OUT/FUZZ_DRIVER_FILE_TARGET" \
  $LIB_FUZZING_ENGINE "$SRC/tinyxml2/build/libout/libtinyxml2.a"
