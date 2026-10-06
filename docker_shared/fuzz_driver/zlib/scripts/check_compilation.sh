#!/bin/bash
project=$1
raw_filename=$2
# Accept either "driver" or "driver.cc" from caller.
filename=${raw_filename%.cc}
cp -f /generated_fuzzer/fuzz_driver/${project}/${filename}.cc /src/${project}/test/
cd /src/${project}
# [ -d /generated_fuzzer/syntax_check_tmp ] || mkdir -p /generated_fuzzer/syntax_check_tmp
#clang -fsyntax-only -w -Wnote -Wextra -pedantic -Iinclude -Isrc/lib  /src/${project}/test/${filename}
$CXX $CXXFLAGS  -w -I/src/${project} -c /src/${project}/test/${filename}.cc -o /src/${project}/test/${filename}.o
