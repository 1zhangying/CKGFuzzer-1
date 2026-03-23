from pathlib import Path
import os

CODEQL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # -> CKGFuzzer-1/
CODEQL_PATH=f"{CODEQL_DIR}/docker_shared/codeql"
def add_codeql_to_path():
    codeql_path = CODEQL_PATH
    current_path = os.environ.get('PATH', '')
    # print(f"Current PATH: {current_path}")
    # Check if CodeQL path is already in PATH1
    if codeql_path not in current_path:
        # Prepend CodeQL to PATH so it takes priority over system-installed versions
        os.environ['PATH'] = codeql_path + os.pathsep + current_path
        print(f"CodeQL has been added to PATH. New PATH: {os.environ['PATH']}")
    else:
        print("CodeQL is already in the PATH.")