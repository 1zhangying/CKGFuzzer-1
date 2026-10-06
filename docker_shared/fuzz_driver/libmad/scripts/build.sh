#!/bin/bash -eu

cd "$SRC"

LIBMAD_CFLAGS="-DNDEBUG -DFPM_INTEL -DSIZEOF_INT=4 -DSIZEOF_LONG=8 -DSIZEOF_LONG_LONG=8"
LIBMAD_SRCS="
libmad/bit.c
libmad/decoder.c
libmad/fixed.c
libmad/frame.c
libmad/huffman.c
libmad/layer12.c
libmad/layer3.c
libmad/stream.c
libmad/synth.c
libmad/timer.c
libmad/version.c
"

mkdir -p "$WORK/libmad_objs"
rm -f "$WORK/libmad_fuzz.a"
for src in $LIBMAD_SRCS; do
  obj_name="${src//\//_}.o"
  $CC $CFLAGS $LIBMAD_CFLAGS \
    -I"$SRC/libmad" \
    -c "$SRC/$src" \
    -o "$WORK/libmad_objs/$obj_name"
  ar rcs "$WORK/libmad_fuzz.a" "$WORK/libmad_objs/$obj_name"
done

$CXX $CXXFLAGS -std=c++11 \
  -I"$SRC/libmad" \
  -c "$SRC/libmad/test/FUZZ_DRIVER_FILE" \
  -o "$WORK/FUZZ_DRIVER_FILE_TARGET.o"

$CXX $CXXFLAGS -std=c++11 "$WORK/FUZZ_DRIVER_FILE_TARGET.o" \
  -o "$OUT/FUZZ_DRIVER_FILE_TARGET" \
  $LIB_FUZZING_ENGINE "$WORK/libmad_fuzz.a" \
  -lm
