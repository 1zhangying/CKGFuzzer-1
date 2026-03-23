#!/bin/bash
project=$1
filename=$2
basename_no_ext="${filename%.*}"
cp -f /generated_fuzzer/fuzz_driver/${project}/${filename} /src/${project}/testbed/
cd /src/${project}
$CXX $CXXFLAGS -w -I/src/${project}/include -c /src/${project}/testbed/${filename} -o /src/${project}/testbed/${basename_no_ext}.o
