#!/bin/bash -eu

cd "$SRC"

FAAD2_CFLAGS="-DSTDC_HEADERS=1 -DHAVE_STDINT_H=1 -DHAVE_STRING_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_MEMCPY=1 -DPACKAGE_VERSION=\"2.8.8\""
FAAD2_SRCS="
faad2/libfaad/bits.c
faad2/libfaad/cfft.c
faad2/libfaad/decoder.c
faad2/libfaad/drc.c
faad2/libfaad/drm_dec.c
faad2/libfaad/error.c
faad2/libfaad/filtbank.c
faad2/libfaad/hcr.c
faad2/libfaad/huffman.c
faad2/libfaad/ic_predict.c
faad2/libfaad/is.c
faad2/libfaad/lt_predict.c
faad2/libfaad/mdct.c
faad2/libfaad/mp4.c
faad2/libfaad/ms.c
faad2/libfaad/output.c
faad2/libfaad/pns.c
faad2/libfaad/ps_dec.c
faad2/libfaad/ps_syntax.c
faad2/libfaad/pulse.c
faad2/libfaad/rvlc.c
faad2/libfaad/sbr_dct.c
faad2/libfaad/sbr_dec.c
faad2/libfaad/sbr_e_nf.c
faad2/libfaad/sbr_fbt.c
faad2/libfaad/sbr_hfadj.c
faad2/libfaad/sbr_hfgen.c
faad2/libfaad/sbr_huff.c
faad2/libfaad/sbr_qmf.c
faad2/libfaad/sbr_syntax.c
faad2/libfaad/sbr_tf_grid.c
faad2/libfaad/specrec.c
faad2/libfaad/ssr.c
faad2/libfaad/ssr_fb.c
faad2/libfaad/ssr_ipqf.c
faad2/libfaad/syntax.c
faad2/libfaad/tns.c
faad2/libfaad/common.c
"

mkdir -p "$WORK/faad2_objs"
rm -f "$WORK/libfaad_fuzz.a"
for src in $FAAD2_SRCS; do
  obj_name="${src//\//_}.o"
  $CC $CFLAGS $FAAD2_CFLAGS \
    -I"$SRC/faad2/include" \
    -I"$SRC/faad2/libfaad" \
    -c "$SRC/$src" \
    -o "$WORK/faad2_objs/$obj_name"
  ar rcs "$WORK/libfaad_fuzz.a" "$WORK/faad2_objs/$obj_name"
done

$CXX $CXXFLAGS -std=c++11 \
  -I"$SRC/faad2/include" \
  -I"$SRC/faad2/libfaad" \
  -c "$SRC/faad2/test/FUZZ_DRIVER_FILE" \
  -o "$WORK/FUZZ_DRIVER_FILE_TARGET.o"

$CXX $CXXFLAGS -std=c++11 "$WORK/FUZZ_DRIVER_FILE_TARGET.o" \
  -o "$OUT/FUZZ_DRIVER_FILE_TARGET" \
  $LIB_FUZZING_ENGINE "$WORK/libfaad_fuzz.a" \
  -lm
