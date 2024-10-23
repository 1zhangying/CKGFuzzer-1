#!/bin/bash

# Get the full path to the script
script_path=$(realpath "$0")

# Extract the directory path
script_dir=$(dirname "$script_path")
cd "$script_dir"
#docker_shared=$(dirname $(dirname "$(dirname "$script_dir")") )

fn_name=$1
fn_file=$2
fn_file="${fn_file//\//_}"
dbbase=$3
pid=$5
echo "Database ====== $script_dir"
echo $dbbase
[ -d $4/call_graph ] || mkdir -p $4/call_graph
outputfile=$4/call_graph/${fn_file}@${fn_name}_call_graph.bqrs
QUERY_TEMPLATE="./extract_call_graph_template.ql"
QUERY="call_graph_${pid}.ql"
# echo "=========="
# echo $PWD
cp $QUERY_TEMPLATE $QUERY
sed -i "s/ENTRY_FNC/$fn_name/g" $QUERY

echo "codeql query run $QUERY --database=$dbbase --output=$outputfile"
codeql query run $QUERY --database=$dbbase --output=$outputfile