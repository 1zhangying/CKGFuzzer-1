#!/bin/bash
set -x
project=$1
filename=$2

# 1. 确保源文件是 .cc
# 如果传来的是 .c，强行看作 .cc
base_name=$(basename "$filename" .c)
base_name=$(basename "$base_name" .cc)
real_file="${base_name}.cc"

# 2. 复制 .cc 文件到测试目录
cp -f /generated_fuzzer/fuzz_driver/${project}/${real_file} /src/${project}/test/

cd /src/${project}

# 3. 【核心修改】构建可执行文件
# 使用 $CXX (clang++) 而不是 $CC
# 链接 LibFuzzer (-fsanitize=fuzzer) 和 AddressSanitizer
# 确保链接了 c-ares 库 (-lcares)
# 强制输出到 out 目录
mkdir -p /src/${project}/out

$CXX $CXXFLAGS -std=c++11 -Iinclude -Isrc/lib \
    -fsanitize=fuzzer,address \
    /src/${project}/test/${real_file} \
    -o /src/${project}/out/${base_name} \
    -L/src/${project}/src/lib/.libs -lcares

# 4. 检查是否构建成功
if [ -f "/src/${project}/out/${base_name}" ]; then
    echo "Build Success: /src/${project}/out/${base_name}"
    # 如果只是构建测试，可以注释掉下面这行运行命令
    # /src/${project}/out/${base_name} -max_total_time=10
else
    echo "Build Failed"
    exit 1
fi
