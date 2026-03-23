#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status.

# Get the full path to the script
script_path=$(realpath "$0")

# Extract the directory path
script_dir=$(dirname "$script_path")
cd "$script_dir"

# Resolve the correct codeql binary relative to this script:
#   script is at docker_shared/qlpacks/cpp_queries/
#   codeql is at docker_shared/codeql/codeql
CODEQL_BIN="$(realpath "$script_dir/../../codeql/codeql")"
if [ ! -x "$CODEQL_BIN" ]; then
    echo "WARNING: Could not find codeql at $CODEQL_BIN, falling back to PATH"
    CODEQL_BIN="codeql"
fi
echo "Using codeql: $CODEQL_BIN ($($CODEQL_BIN --version 2>&1 | head -1))"

fn_name=$1
fn_file=$2
fn_file="${fn_file//\//_}"
dbbase=$3
outputfolder=$4
pid=$5

echo "Database ====== $script_dir"
echo "Database path: $dbbase"
echo "Output folder: $outputfolder"
echo "Process ID: $pid"

[ -d "$outputfolder/call_graph" ] || mkdir -p "$outputfolder/call_graph"
outputfile="$outputfolder/call_graph/${fn_file}@${fn_name}_call_graph.bqrs"



# QUERY_TEMPLATE="./extract_call_graph_template.ql"
# QUERY="call_graph_${pid}.ql"

# 大型项目列表（使用轻量模板）
LARGE_PROJECTS="lcms libtiff libvpx"
# 从数据库路径提取项目名
PROJECT_NAME=$(basename "$dbbase" | sed 's/_[0-9]*$//')
# 根据项目选择模板
if echo "$LARGE_PROJECTS" | grep -qw "$PROJECT_NAME"; then
    QUERY_TEMPLATE="./extract_call_graph_template_lite.ql"
    echo "Using LITE template for large project: $PROJECT_NAME"
else
    QUERY_TEMPLATE="./extract_call_graph_template.ql"
    echo "Using FULL template for project: $PROJECT_NAME"
fi
QUERY="call_graph_${pid}.ql"





echo "Copying template and generating query file..."
cp "$QUERY_TEMPLATE" "$QUERY"
sed -i "s/ENTRY_FNC/$fn_name/g" "$QUERY"


# Limit CodeQL JVM memory to prevent OOM
export CODEQL_JAVA_ARGS="-Xmx4g"

echo "Running query: $CODEQL_BIN query run $QUERY --database=$dbbase --output=$outputfile"
if "$CODEQL_BIN" query run "$QUERY" --database="$dbbase" --output="$outputfile"; then
    echo "Query executed successfully. Converting BQRS to CSV."
    csv_output="${outputfile%.bqrs}.csv"
    if "$CODEQL_BIN" bqrs decode --format=csv "$outputfile" --output="$csv_output"; then
        echo "BQRS file successfully converted to CSV: $csv_output"
    else
        echo "Error converting BQRS to CSV"
        exit 1
    fi
else
    echo "Error executing CodeQL query"
    exit 1
fi

# Clean up the temporary query file
rm "$QUERY"