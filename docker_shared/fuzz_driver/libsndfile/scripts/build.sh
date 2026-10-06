#!/bin/bash -eu

cd "$SRC/libsndfile"

BUILD_DIR="$WORK/libsndfile-build"
CONFIG_DIR="$BUILD_DIR/config"
OBJECT_DIR="$BUILD_DIR/objects"

rm -rf "$BUILD_DIR"
mkdir -p "$CONFIG_DIR" "$OBJECT_DIR"

cat > "$CONFIG_DIR/config.h" <<'EOF'
#define _FILE_OFFSET_BITS 64
#define PACKAGE_NAME "libsndfile"
#define PACKAGE_VERSION "1.0.28"
#define HAVE_STDINT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define HAVE_ENDIAN_H 1
#define HAVE_BYTESWAP_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_LOCALE_H 1
#define HAVE_LRINT 1
#define HAVE_LRINTF 1
#define HAVE_FSTAT64 1
#define HAVE_FSYNC 1
#define HAVE_MMAP 1
#define CPU_IS_BIG_ENDIAN 0
#define CPU_IS_LITTLE_ENDIAN 1
#define CPU_CLIPS_NEGATIVE 0
#define CPU_CLIPS_POSITIVE 0
#define ENABLE_EXPERIMENTAL_CODE 0
#define HAVE_EXTERNAL_XIPH_LIBS 0
#define OS_IS_WIN32 0
#define OS_IS_OPENBSD 0
#define USE_WINDOWS_API 0
#define SIZEOF_LONG 8
#define SIZEOF_LONG_LONG 8
#define SIZEOF_INT64_T 8
#define SIZEOF_SF_COUNT_T 8
#define SIZEOF_WCHAR_T 4
#define TYPEOF_SF_COUNT_T int64_t
EOF

for src in src/*.c src/G72x/*.c src/GSM610/*.c src/ALAC/*.c; do
  base="$(basename "$src")"
  case "$base" in
    test_*.c|g72x_test.c) continue ;;
  esac

  obj="$OBJECT_DIR/${src//\//_}.o"
  "$CC" $CFLAGS \
    -I"$CONFIG_DIR" \
    -I"$SRC/libsndfile/src" \
    -I"$SRC/libsndfile/src/G72x" \
    -I"$SRC/libsndfile/src/GSM610" \
    -I"$SRC/libsndfile/src/ALAC" \
    -c "$src" \
    -o "$obj"
done

ar rcs "$BUILD_DIR/libsndfile.a" "$OBJECT_DIR"/*.o

$CXX $CXXFLAGS -std=c++11 \
  -I"$CONFIG_DIR" \
  -I"$SRC/libsndfile/src" \
  -c "$SRC/libsndfile/test/FUZZ_DRIVER_FILE" \
  -o "$WORK/FUZZ_DRIVER_FILE_TARGET.o"

$CXX $CXXFLAGS -std=c++11 "$WORK/FUZZ_DRIVER_FILE_TARGET.o" \
  -o "$OUT/FUZZ_DRIVER_FILE_TARGET" \
  $LIB_FUZZING_ENGINE "$BUILD_DIR/libsndfile.a" \
  -lm
