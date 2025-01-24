# %%
import os
# %%
from llama_index.core import StorageContext
from llama_index.core.schema import TextNode
from llama_index.core.graph_stores import (
    SimplePropertyGraphStore,
    EntityNode,
    Relation,
)
import pandas as pd
from rag.code_base import get_codebase, CodeRepository
import pandas as pd
import os
import json
from llama_index.vector_stores.chroma import ChromaVectorStore
import chromadb
import nest_asyncio
nest_asyncio.apply()
from llama_index.core.indices.property_graph import (
    LLMSynonymRetriever,
    VectorContextRetriever,
)
from llama_index.core import VectorStoreIndex
from llama_index.llms.ollama import Ollama
from llama_index.core import PropertyGraphIndex
from llama_index.core import Settings
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.core import StorageContext, load_index_from_storage
from loguru import logger

def check_funciton_has_summary(call_src, call_fn, api_summary):
    file_name = os.path.basename(call_src)
    if file_name in api_summary:
        if call_fn in api_summary[file_name]:
            return api_summary[file_name][call_fn]
    return ""

def getCodeCallKGGraph(method_call_csv_file:str, code_base:CodeRepository, api_summary:dict,project_name:str):
    """
    Construct Nodes for Graph Query
    Parameters:
        method_call_csv_file: str, method call relationships csv file.
        code_base: CodeRepository, provides code info
        api_summary: 
    Return: 
        graph_store: SimplePropertyGraphStore
        entities: Entity Nodes in SimplePropertyGraphStore
        all_src_text_nodes: Query index nodes according to the all source code
        summary_text_node: Query index nodes according to the code summary
        api_src_text_nodes:  Query index nodes according to the API source code
    """
    graph_store = SimplePropertyGraphStore()
    # Step 1: Read the CSV file with pandas
    df = pd.read_csv(method_call_csv_file)

    # Step 2: Init Text Node with the specific id. The id has to be the same with EntityNode (name is id)
    entities = []
    relations = []
    methods_in_codebase = [ ] # remove library methods
    all_src_text_nodes = [ ]
    API_src_text_nodes = [ ]
    summary_api_nodes = [ ]
    file_summary_nodes = [ ]
    ids_in_graph = []
    for fn_id in code_base.fn_def:
        parts = fn_id.split("-")
        fid = parts[0]
        method_name = parts[1]
        if method_name == "":
            continue
        methods_in_codebase.append(method_name)

                
    # Step 3: Initialize lists for entities, relations, and source chunks    
    for _, row in df.iterrows():
        caller = row['caller']
        callee = row['callee']
        # if caller == "ares__buf_append" or callee=="ares__buf_append":
        #     print("debug")
            
        caller_src_code = ""
        callee_src_code = ""
        relationship_call = "CALLS"
            
        caller_src = row['caller_src']
        callee_src = row['callee_src']
        if pd.isna(caller_src) or pd.isna(callee_src):
            continue
        callee_src = callee_src.replace(f"/src/{project_name}", "")
        caller_src = caller_src.replace(f"/src/{project_name}", "")
        caller_signature = row['caller_signature']
        callee_signature = row['callee_signature']
        # Step check if the method is in code or from standard or third library
        if caller in methods_in_codebase:
            caller_label = "METHOD"
            caller_src_id = f"{caller_src}-{caller}"
            if caller_src_id in code_base.fn_def:
                caller_src_code = code_base.fn_def[caller_src_id]['code']
                
        else:
            caller_label = "LIBRARY_METHOD"
            relationship_call = "LIBRARY_CALLS"
        
        if callee in methods_in_codebase:
            callee_label = "METHOD"
            callee_src_id = f"{callee_src}-{callee}"
            if callee_src_id in code_base.fn_def:
                callee_src_code = code_base.fn_def[callee_src_id]['code']
               
        else:
            callee_label = "LIBRARY_METHOD"
            relationship_call = "LIBRARY_CALLS"
        
            
        # Step 4: Create entities for the caller and callee
        # add entity caller funciton node 
        if caller_src_code.strip():
            caller_properties = {"signature": caller_signature, "file": caller_src, "source code": f"```code\n{caller_src_code}\n```"} 
        else:
            caller_properties = {"signature": caller_signature, "file": caller_src}
        
        caller_summary = check_funciton_has_summary(caller_src, caller, api_summary)
        if len(caller_summary):
            caller_properties['summary'] = caller_summary
        caller_entity = EntityNode(
            name=f"{caller_src}-{caller}",
            label=caller_label,
            properties=caller_properties
        )
        ids_in_graph.append(f"{caller_src}-{caller}")
        
        # check if file summary in api_summary
        file_name = os.path.basename(caller_src)
        if file_name in api_summary:
            file_summary = api_summary[file_name]["file_summary"]
            file_proerties = {"file summary":file_summary}
        else:
            file_proerties = {}
        caller_file_entity = EntityNode(
            name=f"{caller_src}",
            label="File",
            properties=file_proerties
        )
        ids_in_graph.append(f"{caller_src}")
        
        # add entity calee funciton node 
        if callee_src_code.strip():
            callee_properties = {"signature": callee_signature, "file": callee_src, "source code": f"```code\n{callee_src_code}\n```"}
        else:
            callee_properties =  {"signature": callee_signature, "file": callee_src}
        callee_summary = check_funciton_has_summary(callee_src, callee, api_summary)
        if len(callee_summary):
            callee_properties['summary'] = callee_summary
        callee_entity = EntityNode(
            name=f"{callee_src}-{callee}",
            label=callee_label,
            properties=callee_properties
        )
        
        # check if file summary in api_summary
        file_name = os.path.basename(callee_src)
        if file_name in api_summary:
           file_summary = api_summary[file_name]["file_summary"]
           file_proerties = {"summary":file_summary}
        ids_in_graph.append(f"{callee_src}-{callee}")
        callee_file_entity = EntityNode(
            name=f"{callee_src}",
            label="File",
            properties=file_proerties
        )
        
        ids_in_graph.append(f"{callee_src}")
        entities.extend([caller_entity, callee_entity,caller_file_entity, callee_file_entity])

        # Step 5: Create a relation between caller and callee
        relation = Relation(
            label=relationship_call,
            source_id=caller_entity.id,
            target_id=callee_entity.id,
            properties={}
        )
        file_relation1 = Relation(
            label="CONTAIN",
            source_id=caller_file_entity.id,
            target_id=caller_entity.id,
            properties={}
        )
        file_relation2 = Relation(
            label="CONTAIN",
            source_id=callee_file_entity.id,
            target_id=callee_entity.id,
            properties={}
        )
        relations.append(relation)
        relations.append(file_relation1)
        relations.append(file_relation2)


    # Step 5: Upsert entities, relations, and text nodes into the graph store
    graph_store.upsert_nodes(entities)
    graph_store.upsert_relations(relations)
    # graph_store.upsert_llama_nodes(source_chunks)
    index_ids = []
    unique_index_ids = [ ]
    file_id =[]
    for fn_id in code_base.fn_def:
        parts = fn_id.split("-")
        fid = parts[0]
        method_name = parts[1]
        if method_name == "":
            continue
        # if method_name == "ares__buf_append":
        #     print(k)
        #     print(code_base.fn_def[k])
        #     print("dbug")
        if code_base.fn_def[fn_id]["code"].strip():
            src_node = TextNode(
                id_= fn_id,
                text=code_base.fn_def[fn_id]["code"].strip()
            )
            if fn_id in ids_in_graph and src_node not in all_src_text_nodes:
                all_src_text_nodes.append(src_node)
                index_ids.append(fn_id)    
           
        file_name = os.path.basename(fid)
        if file_name in api_summary:
            for fn_name in api_summary[file_name]:
                if fn_name == "file_summary":
                   sum_node = TextNode(
                        id_= fid,
                        text=api_summary[file_name][fn_name]
                    )
                   if sum_node.id_ in ids_in_graph and sum_node.id_ not in file_id:
                        file_summary_nodes.append(sum_node)
                        file_id.append(sum_node.id_)
                else:
                    sum_node = TextNode(
                        id_= f"{fid}-{fn_name}",
                        text=api_summary[file_name][fn_name]
                    )
                if sum_node.id_ in ids_in_graph and sum_node not in summary_api_nodes:    
                    summary_api_nodes.append(sum_node)
                    index_ids.append(sum_node.id_)
            
            for fn_name in api_summary[file_name]:
                if fn_name == "file_summary":
                    continue
                if f"{fid}-{fn_name}" in code_base.fn_def:
                    api_src_code_node = TextNode(
                        id_= f"{fid}-{fn_name}",
                        text=code_base.fn_def[f"{fid}-{fn_name}"]["code"].strip()
                    )
                    # assert api_src_code_node.id_ not in unique_index_ids
                    unique_index_ids.append(api_src_code_node.id_)
                    # else:
                    #     print(f"Debug {fid}-{fn_name}")
                    if api_src_code_node.id_ in ids_in_graph and api_src_code_node not in API_src_text_nodes:
                        API_src_text_nodes.append(api_src_code_node)
                
            
    # json.dump(ids_in_graph, open("ids_in_graph.json", "w"), indent=2)
    # json.dump(index_ids, open("index_ids.json", "w"), indent=2)
    # json.dump(unique_index_ids, open("unique_index_ids.json", "w"), indent=2)
    # logger.info(f"Number of API_src_text_nodes: {len(API_src_text_nodes)}")
    # logger.info(f"Number of len API_src_text_nodes: {len(list(set([n.id_ for n in API_src_text_nodes])))}")
    return graph_store, entities, all_src_text_nodes, summary_api_nodes,  file_summary_nodes, API_src_text_nodes


def getCodeKG_CodeBase( chromadb_dir: str,  \
                        call_graph_csv:str, src_api_file, api_summary_file,\
                        project_name, saved_folder, \
                        llm, embed_model,\
                        exclude_folder_list, initGraphKG = True, **kwargs):
    """
    Construct the code knowledge graph and code base.

    Parameters:
    - chromadb_dir (str): The directory to store the ChromaDB.
    - call_graph_csv: The path to the call graph CSV file.
    - src_api_file: The path to the source API file.
    - api_summary_file: The path to the API summary file.
    - graph_folder: The folder to store the graph.
    - project_name: The name of the project.
    - saved_folder: The folder to save the knowledge graph.
    - initGraphKG (bool): Whether to initialize the graph knowledge graph. Default is True. This will embed the index ndoes with vectors.
    - exclude_folder_list (list): List of folders to exclude from the code base. Default is ["c-ares/src/tools"].
    - **kwargs: Additional keyword arguments.

    Returns:
    - index_pg_all_code: The index of the code property graph.
    - index_pg_api_summary: The index of the summary property graph.
    - index_pg_api_code: Then index of the code property graph for API functions
    - summary_text_vector_index:
    - all_src_code_vector_index: 
    - code_base: The code base.

    """

    logger.info(f"Constructing code knowledge graph and code base for {project_name}")
    code_base = get_codebase(src_api_file, project_name=project_name, exclude_folder_list=exclude_folder_list)
    api_summary = json.load(open(api_summary_file, "r"))
    if initGraphKG:
        graph_store, entities_nodes, all_src_text_nodes, summary_api_nodes, file_summary_nodes, api_src_text_nodes = getCodeCallKGGraph(\
                call_graph_csv, \
                code_base,\
                api_summary,project_name)
        api_src_vector_index = get_or_construct_chromadb(os.path.join(chromadb_dir, "api_src_text_nodes"), "api_src_text_nodes", api_src_text_nodes, initGraphKG, llm, embed_model)
        api_src_vector = api_src_vector_index._vector_store
        
        all_src_code_vector_index = get_or_construct_chromadb(os.path.join(chromadb_dir, "all_src_text_nodes"), "all_src_text_nodes", all_src_text_nodes, initGraphKG, llm, embed_model)
        all_src_code_vector = all_src_code_vector_index._vector_store
        
        summary_api_vector_index = get_or_construct_chromadb(os.path.join(chromadb_dir, "summary_api_nodes"), "summary_api_nodes", summary_api_nodes, initGraphKG, llm, embed_model)
        summary_api_vector = summary_api_vector_index._vector_store
        
        # file_summary_nodes
        summary_file_vector_index = get_or_construct_chromadb(os.path.join(chromadb_dir, "file_summary_nodes"), "file_summary_nodes", file_summary_nodes, initGraphKG, llm, embed_model)
        summary_file_vector = summary_file_vector_index._vector_store
        
        index_pg_all_code = PropertyGraphIndex.from_existing(\
                    property_graph_store=graph_store, \
                    vector_store=all_src_code_vector, \
                    llm=llm, embed_model=embed_model,\
                    embed_kg_nodes=True, show_progress=True,use_async=False)
        
        index_pg_api_code = PropertyGraphIndex.from_existing(\
                    property_graph_store=graph_store, \
                    vector_store=api_src_vector, \
                    llm=llm, embed_model=embed_model,\
                    embed_kg_nodes=True, show_progress=True,use_async=False)
        
        index_pg_api_summary = PropertyGraphIndex.from_existing(\
                    property_graph_store=graph_store, \
                    vector_store=summary_api_vector,\
                    llm=llm, embed_model=embed_model,\
                    embed_kg_nodes=True, show_progress=True,use_async=False)
        
        index_pg_file_summary = PropertyGraphIndex.from_existing(\
                    property_graph_store=graph_store, \
                    vector_store=summary_file_vector,\
                    llm=llm, embed_model=embed_model,\
                    embed_kg_nodes=True, show_progress=True,use_async=False)
        
        saved_pg_api_code_dir = os.path.join(saved_folder, "kg", "index_pg_api_code")
        saved_pg_all_code_dir = os.path.join(saved_folder, "kg", "index_pg_all_code")
        saved_pg_api_summary_dir = os.path.join(saved_folder, "kg", "index_pg_api_summary")
        saved_pg_file_summary_dir = os.path.join(saved_folder, "kg", "index_pg_file_summary")
        os.makedirs(saved_pg_all_code_dir, exist_ok=True)
        os.makedirs(saved_pg_api_summary_dir, exist_ok=True)
        os.makedirs(saved_pg_api_code_dir, exist_ok=True)
        os.makedirs(saved_pg_file_summary_dir, exist_ok=True)
        index_pg_all_code.storage_context.persist(persist_dir=saved_pg_all_code_dir)
        index_pg_api_summary.storage_context.persist(persist_dir=saved_pg_api_summary_dir)
        index_pg_api_code.storage_context.persist(persist_dir=saved_pg_api_code_dir)
        index_pg_file_summary.storage_context.persist(persist_dir=saved_pg_file_summary_dir)
    else:
        saved_pg_all_code_dir = os.path.join(saved_folder, "kg", "index_pg_all_code")
        saved_pg_api_summary_dir = os.path.join(saved_folder, "kg", "index_pg_api_summary")
        saved_pg_api_code_dir = os.path.join(saved_folder, "kg", "index_pg_api_code")
        saved_pg_file_summary_dir = os.path.join(saved_folder, "kg", "index_pg_file_summary")
        
        all_src_code_vector_index = get_or_construct_chromadb(os.path.join(chromadb_dir, "all_src_text_nodes"), "all_src_text_nodes", all_src_text_nodes, initGraphKG, llm, embed_model)
        
        summary_api_vector_index = get_or_construct_chromadb(os.path.join(chromadb_dir, "summary_api_nodes"), "summary_api_nodes", summary_api_nodes, initGraphKG, llm, embed_model)
        
        api_src_vector_index = get_or_construct_chromadb(os.path.join(chromadb_dir, "api_src_text_nodes"), "api_src_text_nodes", api_src_text_nodes, initGraphKG, llm, embed_model)
        
        summary_file_vector_index = get_or_construct_chromadb(os.path.join(chromadb_dir, "file_summary_nodes"), "file_summary_nodes", file_summary_nodes, initGraphKG, llm, embed_model)

        
        index_pg_all_code = PropertyGraphIndex.from_existing(\
                        property_graph_store = SimplePropertyGraphStore.from_persist_dir(saved_pg_all_code_dir), \
                        vector_store=all_src_code_vector_index._vector_store, \
                        embed_kg_nodes=True, show_progress=True, \
                        llm=llm, embed_model=embed_model, **kwargs)
        index_pg_api_summary = PropertyGraphIndex.from_existing(\
                        property_graph_store = SimplePropertyGraphStore.from_persist_dir(saved_pg_api_summary_dir), \
                        vector_store=summary_api_vector_index._vector_store,\
                        embed_kg_nodes=True, show_progress=True, \
                        llm=llm, embed_model=embed_model, **kwargs)
        index_pg_api_code = PropertyGraphIndex.from_existing(\
                        property_graph_store = SimplePropertyGraphStore.from_persist_dir(saved_pg_api_summary_dir), \
                        vector_store=api_src_vector_index._vector_store,\
                        embed_kg_nodes=True, show_progress=True, \
                        llm=llm, embed_model=embed_model, **kwargs)
        index_pg_file_summary = PropertyGraphIndex.from_existing(\
                        property_graph_store = SimplePropertyGraphStore.from_persist_dir(saved_pg_file_summary_dir), \
                        vector_store=summary_file_vector_index._vector_store,\
                        embed_kg_nodes=True, show_progress=True, \
                        llm=llm, embed_model=embed_model, **kwargs)
        
    return index_pg_all_code, index_pg_api_summary, index_pg_api_code, index_pg_file_summary, summary_api_vector_index, all_src_code_vector_index, api_src_vector_index, code_base

def get_or_construct_chromadb(chromadb_dir: str, chromadb_name: str, nodes: list[TextNode], initVector: bool, llm, embed_model) -> VectorStoreIndex:
    """
    Retrieves an existing ChromaVectorStore from the specified ChromaDB directory and name,
    or constructs a new one if initVector is set to True.

    Args:
        chromadb_dir (str): The directory where the ChromaDB is located.
        chromadb_name (str): The name of the ChromaDB.
        nodes (list[TextNode]): A list of TextNode objects.
        initVector (bool): Whether to initialize the ChromaVectorStore with the given nodes.

    Returns:
        ChromaVectorStore: The retrieved or constructed ChromaVectorStore object.
    """
    print(f"Constructing ChromaDB for {chromadb_name}")
    print(f"ChromaDB directory: {chromadb_dir}")
    client = chromadb.PersistentClient(chromadb_dir)
    collection = client.get_or_create_collection(chromadb_name)
    cvs = ChromaVectorStore(chroma_collection=collection)
    if initVector:
        Settings.llm=llm
        Settings.embed_model=embed_model
        storage_context = StorageContext.from_defaults(vector_store=cvs)
        # nodes_len = len(nodes)
        # nodes_idls = [ n.id_ for n in nodes ]
        # assert len(set(nodes_idls)) == nodes_len
        vector_index = VectorStoreIndex(nodes, storage_context=storage_context)
        cvs = vector_index._vector_store
    else:
        storage_context = StorageContext.from_defaults(vector_store=cvs)
        vector_index = VectorStoreIndex.from_vector_store(
                        cvs, storage_context=storage_context )
    return vector_index


class VulnerabilityReport:
    def __init__(self, index, kv_map) -> None:
        self.index = index
        self.kv_map = kv_map
        

def read_vul_vector(vulnerability_file, chromadb_dir, llm, embed_model, initVector=True):
    data = json.load(open(vulnerability_file, "r") )
    vul_nodes = []
    vul_dict = {}
    for cwe_id, cwe in data.items():
        # print(cwe_id)
        # print(cwe)
        example_vul_code = cwe["Code Example"]["code"]
        vul_description = cwe["Code Example"]["summary"]
        if vul_description is not None:
            vul_description = str(vul_description)
        node = TextNode(
                        id_= f"{cwe_id}",
                        text=example_vul_code,
                        metadata={"vul description": vul_description}
                    )
        vul_nodes.append(node)
        vul_dict[cwe_id] = vul_description
    vul_index = get_or_construct_chromadb(os.path.join(chromadb_dir, "vulnerability_data"), "vulnerability_data", vul_nodes, initVector, llm, embed_model)
    return VulnerabilityReport(vul_index, vul_dict)    
