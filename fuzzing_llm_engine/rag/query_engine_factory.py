
import os
from llama_index.core import StorageContext, load_index_from_storage, SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core.postprocessor import SimilarityPostprocessor
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core import get_response_synthesizer
from llama_index.core import Settings
import pdb
from loguru import logger
from rag.kg import getCodeKG_CodeBase,read_vul_vector


def build_test_query(database_dir, llm=None, embed_model=None):

    Settings.llm=llm
    Settings.embed_model=embed_model
    test_case_index_dir = os.path.join(database_dir, "test_case_index")
    test_dir = os.path.join(database_dir, "test")
    if os.path.exists(test_case_index_dir):
        logger.info(f"Loading from {test_case_index_dir}")
        test_case_storage_context = StorageContext.from_defaults(persist_dir=test_case_index_dir)
        test_case_index = load_index_from_storage(test_case_storage_context, show_progress=True)

    else:
        logger.info(f"Construct from {test_dir}")
        test_case_documents = SimpleDirectoryReader(test_dir, raise_on_error=True).load_data()
        test_case_index = VectorStoreIndex.from_documents(
            test_case_documents,
            transformations=[SentenceSplitter(chunk_size=512, chunk_overlap=30)],
            show_progress=True
        )
        test_case_index.storage_context.persist(persist_dir=test_case_index_dir)
       
    return test_case_index


def build_cwe_query(cwe_database_dir, llm=None, embed_model=None):
    Settings.llm = llm
    Settings.embed_model = embed_model
    cwe_data_dir=os.path.join(cwe_database_dir,"vul_code")
    cwe_index_dir = os.path.join(cwe_database_dir, "cwe_index")
    if os.path.exists(cwe_index_dir):
        logger.info(f"Loading CWE index from {cwe_index_dir}")
        cwe_storage_context = StorageContext.from_defaults(persist_dir=cwe_index_dir)
        cwe_index = load_index_from_storage(cwe_storage_context, show_progress=True)
    else:
        logger.info(f"Constructing CWE index from {cwe_data_dir}")
        cwe_documents = SimpleDirectoryReader(cwe_data_dir, raise_on_error=True).load_data()
        cwe_index = VectorStoreIndex.from_documents(
            cwe_documents,
            transformations=[SentenceSplitter(chunk_size=512, chunk_overlap=30)],
            show_progress=True
        )
        cwe_index.storage_context.persist(persist_dir=cwe_index_dir)
    return cwe_index


def build_kg_query(chromadb_dir: str,  \
                        call_graph_csv:str, src_api_file, api_summary_file,\
                        project_name, saved_folder, \
                        exclude_folder_list,initGraphKG = True, \
                             llm = None, embed_model = None, **kwargs):
    if llm is None:
       llm = Settings.llm
    if embed_model is None:
        embed_model = Settings.embed_model
    # TODO: Use custom prompt by setting **kwargs
    # index_pg_all_code, index_pg_api_summary, index_pg_api_code, index_pg_file_summary, summary_api_vector_index, all_src_code_vector_index, api_src_vector_index, code_base
    index_pg_all_code, index_pg_api_summary, index_pg_api_code, index_pg_file_summary, summary_api_vector_index, all_src_code_vector_index, api_src_vector_index, code_base = getCodeKG_CodeBase(
                        chromadb_dir, \
                        call_graph_csv, src_api_file, api_summary_file,\
                        project_name, saved_folder, llm, embed_model, \
                        exclude_folder_list=exclude_folder_list,initGraphKG = initGraphKG, **kwargs)
    
    return index_pg_all_code, index_pg_api_summary, index_pg_api_code, index_pg_file_summary,summary_api_vector_index, all_src_code_vector_index, api_src_vector_index, code_base


def build_vul_query(chromadb_dir, vul_report_file, llm = None, embed_model = None, initVector=True):
    vul_vector_report = read_vul_vector(vul_report_file, chromadb_dir, llm = llm, embed_model = embed_model, initVector=initVector)
    return vul_vector_report