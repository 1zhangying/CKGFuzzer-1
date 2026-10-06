#!/bin/bash

set -e

project=$1
raw_filename=$2

case "$raw_filename" in
  *.c|*.cc|*.cpp) filename="$raw_filename" ;;
  *) filename="${raw_filename}.cc" ;;
esac

target="${filename%.*}"
mkdir -p "/src/${project}/test"
cp -f "/generated_fuzzer/fuzz_driver/${project}/${filename}" "/src/${project}/test/${filename}"
cd "/src/${project}"

$CXX $CXXFLAGS -w \
  -I/src/${project}/expat/lib \
  -I/src/${project}/build \
  -c "/src/${project}/test/${filename}" \
  -o "/src/${project}/test/${target}.o"
