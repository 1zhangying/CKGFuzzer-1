#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################


mkdir -p build
cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF ..
make -j$(nproc)

$CC $CFLAGS -c $SRC/cjson/fuzzing/cjson_fuzz_driver_False_qwen3-coder-plus_59.cc -I$SRC/cjson -o cjson_fuzz_driver_False_qwen3-coder-plus_59.o
$CXX $CXXFLAGS -std=c++11  cjson_fuzz_driver_False_qwen3-coder-plus_59.o -o $OUT/cjson_fuzz_driver_False_qwen3-coder-plus_59 \
    $LIB_FUZZING_ENGINE ./libcjson.a

