#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status.

# Get the full path to the script
script_path=$(realpath "$0")

# Extract the directory path
script_dir=$(dirname "$script_path")
cd "$script_dir"

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
QUERY_TEMPLATE="./extract_call_graph_template.ql"
QUERY="call_graph_${pid}.ql"


echo "Copying template and generating query file..."
cp "$QUERY_TEMPLATE" "$QUERY"
sed -i "s/ENTRY_FNC/$fn_name/g" "$QUERY"


echo "Running query: codeql query run $QUERY --database=$dbbase --output=$outputfile"
if codeql query run "$QUERY" --database="$dbbase" --output="$outputfile"; then
    echo "Query executed successfully. Converting BQRS to CSV."
    csv_output="${outputfile%.bqrs}.csv"
    if codeql bqrs decode --format=csv "$outputfile" --output="$csv_output"; then
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