#!/bin/bash
project=$1
filename=$2
# filename now includes extension (e.g. xxx.cc or xxx.c)
basename_no_ext="${filename%.*}"
cp -f /generated_fuzzer/fuzz_driver/${project}/${filename} /src/${project}/tests/
cd /src/${project}
$CC $CFLAGS -w -I/src/${project} -c /src/${project}/tests/${filename} -o /src/${project}/tests/${basename_no_ext}.o
