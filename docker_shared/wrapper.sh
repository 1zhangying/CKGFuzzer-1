#!/bin/bash

# Call your script. Replace 'your_script.sh' with the actual script name


cd /src/$1
# Path to the build.sh script
script_path=/src/build.sh

# Check if the file exists
if [ ! -f "$script_path" ]; then
    echo "Error: File '$script_path' does not exist."
    exit 1
fi

# Use grep to search for the command
if grep -q "bazel_build_fuzz_tests" "$script_path"; then
    echo "The command 'bazel_build_fuzz_tests' is found in '$script_path'."
    cp /src/fuzzing_os/bazel_build /usr/local/bin/
    sed -i 's/exec bazel_build_fuzz_tests/exec bazel_build/g' $script_path
    #script_path=/src/fuzzing_os/bazel_build.sh
else
    echo "The command 'bazel_build_fuzz_tests' is not found in '$script_path'."
fi

bash $script_path
# Override the exit code
exit 0
