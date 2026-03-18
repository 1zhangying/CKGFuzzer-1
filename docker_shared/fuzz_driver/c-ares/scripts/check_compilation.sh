#!/bin/bash
set -x
project=$1
filename=$2

# 1. 强制找 .cc 文件
# 注意：这里我们让它去拿 .cc，配合你 Python 代码生成的 .cc
cp -f /generated_fuzzer/fuzz_driver/${project}/${filename}.cc /src/${project}/test/

cd /src/${project}

# 2. 编译 .cc 文件
# 使用 $CC 或 clang++ 编译
$CC $CFLAGS -w -Iinclude -Isrc/lib -c /src/${project}/test/${filename}.cc -o /src/${project}/test/${filename}.o
