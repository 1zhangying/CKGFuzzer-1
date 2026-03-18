from pathlib import Path
import os

CODEQL_DIR = os.path.abspath("../..")  # Adjust the number of parents based on submodule depth
CODEQL_PATH=f"{CODEQL_DIR}/docker_shared/codeql"
def add_codeql_to_path():
    codeql_path = CODEQL_PATH
    current_path = os.environ.get('PATH', '')
    # print(f"Current PATH: {current_path}")
    # Check if CodeQL path is already in PATH1
    if codeql_path not in current_path:
        # Adding CodeQL to PATH
        os.environ['PATH'] += os.pathsep + codeql_path
        print(f"CodeQL has been added to PATH. New PATH: {os.environ['PATH']}")
    else:
        print("CodeQL is already in the PATH.")