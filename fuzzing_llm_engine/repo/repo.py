## agent_repo.py
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取父目录
parent_dir = os.path.dirname(current_dir)
# 将父目录添加到 sys.path
sys.path.insert(0, parent_dir)
#from pathlib import Path
import getpass
from loguru import logger
import json    
from typing import List, Dict
from utils.docker_run import docker_run, check_image_exists, create_image
from utils.query_dp import run_query, run_converted_csv,run_command, add_codeql_to_path
import subprocess
from utils import check_create_folder, check_path_test, find_cpp_head_files
# from pandas import DataFrame
# import pandas as pd
from loguru import logger
from codetext.parser.cpp_parser import CppParser
# from tools.codetext.utils import build_language, parse_code
import collections
from multiprocessing import Pool,Manager
from tqdm import tqdm
import shutil

add_codeql_to_path()
# Get the current PATH
current_path = os.environ['PATH']
logger.info(f"PATH: {current_path}")
logger.add("repo_log.txt")

from utils.repo_fn import clean_label, change_folder_owner, get_all_files, copy_file_to_tmp_get_definition
        
manager = Manager() 
# created a size limited queue
queue_id = manager.Queue()


import shutil

import chardet

            
class RepositoryAgent:
    def __init__(self, args: Dict = None):
        """
        Initializes the PlanningAgent with the extracted API information.

        Args:
            api_info (Dict, optional): Extracted API information to be used for planning fuzzing tasks. Defaults to None.
        """
        super().__init__()
        self.args = args
        self.shared_llm_dir = args.shared_llm_dir
        self.src_folder = f'{args.shared_llm_dir}/source_code/{args.project_name}'
        self.queryes_folder = f'{args.shared_llm_dir}/qlpacks/cpp_queries/'
        self.database_db = f'{args.shared_llm_dir}/codeqldb/{args.project_name}'
        self.output_results_folder = f'{args.saved_dir}'
        check_create_folder(self.output_results_folder)

        
        self.init_repo()
        

    def init_repo(self) -> List[str]:
        """
        Initializes the repository with the provided arguments.
            1. Add the repo to the database codeql.
            2. Extract API Info.
        """
        if os.path.isfile(f'{args.shared_llm_dir}/codeqldb/{args.project_name}/.successfully_created'):
            logger.info(f"Database for {args.project_name} already exists.")
            # print(f"Database for {args.project_name} already exists.")
        else:
            self._add_local_repo_to_database(self.args)
        
        if not os.path.isdir(f'{self.src_folder}'):
            logger.info(f"{args.project_name} does not exist.")
            self.copy_source_code_fromDocker()


    def _add_local_repo_to_database(self, args: Dict) -> None:
        USER_NAME = getpass.getuser()
        project_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'projects', args.project_name)
        dockerfile_path = os.path.join(project_dir, 'Dockerfile')

        if not os.path.exists(dockerfile_path):
            raise FileNotFoundError(f"Dockerfile not found at {dockerfile_path}")

        image_name = f'{args.project_name}_base_image'
        build_command = f'docker build -t {image_name} -f {dockerfile_path} {project_dir}'
        
        try:
            subprocess.run(build_command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to build Docker image: {e}")
            return

        # Prepare the CodeQL command
        codeql_command = f'/src/fuzzing_os/codeql/codeql database create /src/fuzzing_os/codeqldb/{args.project_name} --language={args.language}'
        
        if args.language in ['c', 'cpp', 'c++', 'java', 'csharp', 'go', 'java-kotlin']:
            codeql_command += f' --command="/src/fuzzing_os/wrapper.sh {args.project_name}"'

        # Run the Docker container with the CodeQL command
        command = [
            'docker', 'run', '--rm',
            '-v', f'{args.shared_llm_dir}:/src/fuzzing_os',
            '-t', image_name,
            '/bin/bash', '-c', codeql_command
        ]

        result = subprocess.run(command, capture_output=True, text=True)

        change_folder_owner(f"{args.shared_llm_dir}/change_owner.sh", f'{args.shared_llm_dir}/codeqldb/{args.project_name}', USER_NAME)

        if f"Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}" in result.stdout:
            with open(f'{args.shared_llm_dir}/codeqldb/{args.project_name}/.successfully_created', 'w') as f:
                f.write('')
            logger.info(result.stdout)
            logger.info(f"Confirmed Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}")
        else:
            print(result.stdout)
            print(result.stderr)
            assert False, f"Failed to create database at /src/fuzzing_os/codeqldb/{args.project_name}"

    def _add_repo_to_database(self, args: Dict) -> None:
        image_name = f'gcr.io/oss-fuzz/{args.project_name}'
        if not check_image_exists(image_name):
            create_image(args.project_name)
            
        # USER_NAME = getpass.getuser()
        if args.language in ['c','cpp', 'java', 'csharp','go', 'java-kotlin']:
            logger.info(f"args.shared_llm_dir {args.shared_llm_dir}")
            command = ['-v', f'{os.path.abspath(args.shared_llm_dir)}:/src/fuzzing_os', '-t', f'gcr.io/oss-fuzz/{args.project_name}', '/bin/bash', '-c', f'/src/fuzzing_os/codeql/codeql database create /src/fuzzing_os/codeqldb/{args.project_name} --language={args.language}  --command="/src/fuzzing_os/wrapper.sh {args.project_name}" && chown -R 1000:1000 /src/fuzzing_os/codeqldb/{args.project_name}' ] # --command="/src/fuzzing_os/wrapper.sh {args.project_name} --source-root={args.project_name}
        else:
            command = ['-v', f'{os.path.abspath(args.shared_llm_dir)}:/src/fuzzing_os', '-t', f'gcr.io/oss-fuzz/{args.project_name}', '/bin/bash', '-c', f'/src/fuzzing_os/codeql/codeql database create /src/fuzzing_os/codeqldb/{args.project_name} --language={args.language} && chown -R 1000:1000 /src/fuzzing_os/codeqldb/{args.project_name}' ] # --source-root={args.project_name}
        result,_ = docker_run(command, print_output=True, architecture='x86_64')
        #change_folder_owner(f"{args.shared_llm_dir}/change_owner.sh",f'{args.shared_llm_dir}/codeqldb/{args.project_name}', USER_NAME)
        if f"Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}" in result:
            with open(f'{args.shared_llm_dir}/codeqldb/{args.project_name}/.successfully_created', 'w') as f:
                f.write('')
            logger.info(result)
            logger.info(f"Confirmed Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}")
        else:
            logger.info(result)
            logger.info(f"Failed to create database at /src/fuzzing_os/codeqldb/{args.project_name}" )
            assert False, f"Failed to create database at /src/fuzzing_os/codeqldb/{args.project_name}"    
    

    # read the function name and its source code name from the returned dict of extract_api_from_head
    def extract_src_test_api_call_graph(self, data: Dict, pool_num=4) -> Dict:
        """
        ToDO: multple thread SUPPORT, need to keep the copy database for each thread
        Extracts the source and test API information from the repository.
        """
        logger.info("Extracting source and test API information from the repository.")
        src_api = []
        for src_file in data['src']:
            fn_def_list = data['src'][src_file]['fn_def_list']
            for item in fn_def_list:
                fn_name = item['fn_meta']['identifier']
                src_api.append((fn_name, src_file.replace(f'{args.shared_llm_dir}/source_code/', '/src/')))
        
        eggs = [ (api[0].strip(), api[1].strip(), self.database_db, self.output_results_folder, self.shared_llm_dir) for api in src_api ]
        logger.info(f"Total number of API to be processed: {len(eggs)}")
        logger.info("Copy Database for each thread.")
        for i in tqdm(range(pool_num)):
            shutil.copytree(self.database_db, f'{self.database_db}_{i}', dirs_exist_ok=True)
            queue_id.put(i)

        with Pool(pool_num) as pool:   
            results = list(tqdm(pool.imap(RepositoryAgent.handle_extract_api_call_graph_multiple_path, eggs), total=len(eggs), desc='Processing transactions'))     
          
        for i in range(pool_num):
            shutil.rmtree(f'{self.database_db}_{i}')

    @staticmethod
    def handle_extract_api_call_graph_multiple_path(item):
        global queue_id
        pid = os.getpid()  # Get the current process ID
        bid = queue_id.get()
        logger.info(f"============================ {pid} Consuming {bid}")
        fn_name, fn_file_name, dbbase, outputfolder, shared_llm_dir = item
        RepositoryAgent._extract_call_graph(shared_llm_dir, fn_name, fn_file_name, f"{dbbase}_{bid}", outputfolder, bid)
        queue_id.put(bid)

    @staticmethod
    def _extract_call_graph(shared_llm_dir, fn_name, fn_file_name, dbbase, outputfolder, pid):
        """
        Extracts the call graph from the repository.
        """
        logger.info("Extracting call graph from the repository.")
        extract_shell_script = f"{shared_llm_dir}/qlpacks/cpp_queries/extract_call_graph.sh"
        pname = fn_file_name.replace('/', '_')
        if os.path.isfile(extract_shell_script):
            if not os.path.isfile(f"{outputfolder}/call_graph/{pname}@{fn_name}_call_graph.bqrs"):
                logger.info(f"{outputfolder}/call_graph/{pname}@{fn_name}_call_graph.bqrs")
                # convert dbbase and outputfolder to the absolute path
                dbbase = os.path.abspath(dbbase)
                outputfolder = os.path.abspath(outputfolder)
                #fn_name="ares__dns_options_free"
                logger.info(f"Extracting call graph for {fn_name} in {fn_file_name}.")
                run_command([extract_shell_script, fn_name, fn_file_name, dbbase, outputfolder, str(pid)])
                logger.info("Call graph is converted into the csv file.")
                #fn_file="${fn_file//\//_}"
            if not os.path.isfile(f"{outputfolder}/call_graph/{pname}@{fn_name}_call_graph.csv"):
                run_converted_csv(f"{outputfolder}/call_graph/{pname}@{fn_name}_call_graph.bqrs")  
        else:
            assert False, f"Extract call graph shell script {extract_shell_script} does not exist. PWD {os.getcwd()}"
              
    def copy_source_code_fromDocker(self):
        """
        Extracts the source code from the repository.
        """
        logger.info("Extracting source code from the repository.")
        
        # First, create the necessary directories
        mkdir_command = ['-v', f'{os.path.abspath(args.shared_llm_dir)}:/src/fuzzing_os', 
                        '-t', f'{args.project_name}_base_image', 
                        '/bin/bash', '-c', 
                        f'mkdir -p /src/fuzzing_os/source_code/{args.project_name}']
        docker_run(mkdir_command)
        
        # Then, copy the source code
        copy_command = ['-v', f'{os.path.abspath(args.shared_llm_dir)}:/src/fuzzing_os', 
                        '-t', f'{args.project_name}_base_image', 
                        '/bin/bash', '-c', 
                        f'cp -rf /src/{args.project_name}/* /src/fuzzing_os/source_code/{args.project_name} && '
                        f'chown -R 1000:1000 /src/fuzzing_os/source_code/{args.project_name}']
        docker_run(copy_command)



    def scan_vulnerability_qlCWE(self):
        """
        Scan the repository for vulnerabilities.
        """
        logger.info("Scanning the repository for vulnerabilities.")
        os.makedirs(f'{self.output_results_folder}/vulnerability', exist_ok=True)
        output_file = f'{self.output_results_folder}/vulnerability/CWE.sarif'
        command = [ "codeql", "database", "analyze", f"{self.database_db}","codeql/cpp-queries:codeql-suites/cpp-security-extended.qls", "--format=sarifv2.1.0", f"--output={output_file}", "--download" ]
        run_command(command)
    
    def scan_vulnerability_extended_CWE(self):
        """
        Scan the repository for the extened vulnerabilities.
        """
        logger.info("Scanning the repository for extended vulnerabilities.")
        os.makedirs(f'{self.output_results_folder}/vulnerability', exist_ok=True)
        output_file = f'{self.output_results_folder}/vulnerability/CWE_extend.sarif'
        command = [ "codeql", "database", "analyze", f"{self.database_db}","codeql/cpp-queries:codeql-suites/cpp-code_qlrules.qls", "--format=sarif", f"--output={output_file}", "--download"]
        run_command(command)
    
    def extract_api_from_head(self):
        if not os.path.isdir(self.src_folder):
            logger.info(f"{self.src_folder} does not exist.")
            self.copy_source_code_fromDocker()
        logger.info(f"Extracting API information from the source code. {self.src_folder}")
        src_dic, test_dic = find_cpp_head_files(self.src_folder)    


        logger.info(f"Number of source files: {len(src_dic['src'])}")
        logger.info(f"Number of header files: {len(src_dic['head'])}")
    
        if not src_dic['head']:
            logger.warning("No header files found!")
      
            for root, dirs, files in os.walk(self.src_folder):
                logger.debug(f"Directory: {root}")
                for file in files:
                    logger.debug(f"File: {os.path.join(root, file)}")

        logger.info("Extracting API information from the source code.")
        result_src = self._extract_API(src_dic)
        logger.info("Extracting API information from the test code.")
        result_test= self._extract_API(test_dic)
        logger.info(f"Store API to {self.output_results_folder}/api/")
        os.makedirs(f'{self.output_results_folder}/api', exist_ok=True)
        json.dump(result_src, open(f'{self.output_results_folder}/api/src_api.json', 'w'), indent=2)
        json.dump(result_test, open(f'{self.output_results_folder}/api/test_api.json', 'w'), indent=2)
        return result_src, result_test
    
    import chardet

    def _extract_API(self, src_dic):
        result = collections.defaultdict(dict)
        for k in ['src', 'head']:
            logger.info(f"Processing {k} files")
            for src in src_dic[k]:
                logger.info(f"Processing file: {src}")
                try:
                
                    with open(src, 'r', encoding='utf-8') as file:
                        code = file.read()
                except UnicodeDecodeError:
                 
                    with open(src, 'rb') as file:
                        raw = file.read()
                        detected = chardet.detect(raw)
                        encoding = detected['encoding']
                    
                   
                    try:
                        code = raw.decode(encoding)
                    except:
                        logger.error(f"Failed to decode {src} with detected encoding {encoding}. Skipping this file.")
                        continue

                try:
                    fn_def_list, fn_declaraion, class_node_list, struct_node_list, include_list, global_variables, enumerate_node_list = CppParser.split_code(code, is_return_node=False)
                    result[k][src] = {
                        'fn_def_list': fn_def_list,
                        'fn_declaraion': fn_declaraion,
                        'class_node_list': class_node_list,
                        'struct_node_list': struct_node_list,
                        'include_list': include_list,
                        "global_variables": global_variables,
                        "enumerate_node_list": enumerate_node_list
                    }
                    logger.info(f"Successfully processed {src}")
                    logger.info(f"Found {len(fn_def_list)} function definitions, {len(fn_declaraion)} function declarations, {len(class_node_list)} classes, {len(struct_node_list)} structs")
                
              
                    debug_output_path = f'{src}.debug.json'
                    with open(debug_output_path, 'w') as f:
                        json.dump(result[k][src], f, indent=2)
                    logger.info(f"Debug output written to {debug_output_path}")
                
                except Exception as e:
                    logger.error(f"Error processing {src}: {str(e)}")
                    continue

        logger.info(f"Finished processing all files. Found data for {len(result['src'])} source files and {len(result['head'])} header files.")
        return result
    




import os    
import argparse
import repo.constants as constants

def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Example application")
    parser.add_argument('--project_name', type=str, default="c-ares", help='Project Name')
    parser.add_argument('--shared_llm_dir', type=str, default="../docker_shared", help='Shared LLM Directory')
    parser.add_argument('--saved_dir', type=str, default="./external_database/c-ares/codebase", help='Saved Directory')
    parser.add_argument('--language', type=str, default="c++", help='Language')
    parser.add_argument('--build_command', type=str, default="/src/fuzzing_os/build_c_ares.sh", help='Build command')
    parser.add_argument('--project_build_info', type=str, default=None, help='Build information of the project')
    parser.add_argument('--environment_vars', dest='environment_vars', action='append', help="Set environment variable e.g., VAR=value")
    parser.add_argument('--engine', default=constants.DEFAULT_ENGINE, choices=constants.ENGINES, help='Engine used for building')
    parser.add_argument('--architecture', default=constants.DEFAULT_ARCHITECTURE, choices=constants.ARCHITECTURES, help='CPU architecture')
    parser.add_argument('--sanitizer', default=None, choices=constants.SANITIZERS, help='Sanitizer type')
    parser.add_argument('--src_api', action='store_true', help='Source API')
    parser.add_argument('--test_api', action='store_true', help='Test API version')
    parser.add_argument('--call_graph', action='store_true', help='Call graph')
    parser.add_argument('--cwe_scan', action='store_true', help='CWE Scan')
    return parser
    
if __name__ == "__main__":
    parser = setup_parser()
    args = parser.parse_args()
    r = RepositoryAgent(args)
    
    logger.info(f"The current work path is: {os.getcwd()}")
    result_src, result_test = None, None
    if args.src_api:
        result_src, result_test = r.extract_api_from_head()
    
    
    if args.cwe_scan:
        r.scan_vulnerability_qlCWE()
        # r.scan_vulnerability_extended_CWE()
    
    if args.call_graph:
        if result_src is None and result_test is None:
            result_src, result_test = r.extract_api_from_head()
        r.extract_src_test_api_call_graph(result_src)
        

 
  