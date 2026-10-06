#!/bin/bash -eu

cd "$SRC/libmspack"

# Docker COPY can disturb autotools timestamps and make tries to rerun aclocal-1.15.
touch aclocal.m4 configure Makefile.in config.h.in

./configure CFLAGS="$CFLAGS" --disable-shared --enable-static
make -j$(nproc) ACLOCAL=true AUTOCONF=true AUTOHEADER=true AUTOMAKE=true libmspack.la

$CXX $CXXFLAGS -std=c++11 \
  -I"$SRC/libmspack" \
  -I"$SRC/libmspack/mspack" \
  -c "$SRC/libmspack/test/FUZZ_DRIVER_FILE" \
  -o "$WORK/FUZZ_DRIVER_FILE_TARGET.o"

$CXX $CXXFLAGS -std=c++11 "$WORK/FUZZ_DRIVER_FILE_TARGET.o" \
  -o "$OUT/FUZZ_DRIVER_FILE_TARGET" \
  $LIB_FUZZING_ENGINE "$SRC/libmspack/.libs/libmspack.a"
