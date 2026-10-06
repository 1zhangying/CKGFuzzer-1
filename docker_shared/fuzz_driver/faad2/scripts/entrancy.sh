#!/bin/bash

set -e

remove_suffix() {
  local filename="$1"
  echo "${filename%.*}"
}

fuzz_driver_file=$1
project_name=$2
fuzz_driver_base=$(remove_suffix "$fuzz_driver_file")

mkdir -p "$SRC/${project_name}/test"
cp /generated_fuzzer/fuzz_driver/${project_name}/scripts/build.sh "$SRC/build.sh"
cp -f /generated_fuzzer/fuzz_driver/${project_name}/compilation_pass_rag/${fuzz_driver_file} \
  "$SRC/${project_name}/test/${fuzz_driver_file}"

sed -i "s/FUZZ_DRIVER_FILE_TARGET/$fuzz_driver_base/g" "$SRC/build.sh"
sed -i "s/FUZZ_DRIVER_FILE/$fuzz_driver_file/g" "$SRC/build.sh"

export FUZZ_FILE="${fuzz_driver_file}"
export FUZZ_TARGET="${fuzz_driver_base}"
