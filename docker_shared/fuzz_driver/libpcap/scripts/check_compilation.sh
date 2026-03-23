#!/bin/bash
project=$1
filename=$2
basename_no_ext="${filename%.*}"
cp -f /generated_fuzzer/fuzz_driver/${project}/${filename} /src/${project}/tests/
cd /src/${project}
$CXX $CXXFLAGS -w -I/src/${project} -c /src/${project}/tests/${filename} -o /src/${project}/tests/${basename_no_ext}.o
