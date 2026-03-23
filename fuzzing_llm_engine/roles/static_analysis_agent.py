import sys
from pathlib import Path
import os
import re
from tree_sitter import Language, Parser
from llama_index.core.prompts import PromptTemplate
from llama_index.core import Settings
from llama_index.core.memory import (
    VectorMemory,
    SimpleComposableMemory,
    ChatMemoryBuffer,
)
from llama_index.core.llms import ChatMessage
from loguru import logger

# Get the current file path and tree-sitter location
if "TREE_SITTER" not in os.environ:
    current_file_path = os.path.abspath(__file__)
    tree_folder = os.path.dirname(os.path.dirname(current_file_path))
else:
    tree_folder = os.environ["TREE_SITTER"]

_CPP_SO_PATH = os.path.join(tree_folder, "codetext/parser/tree-sitter/cpp.so")
_CPP_GRAMMAR_DIR = os.path.join(tree_folder, "codetext/parser/tree-sitter/tree-sitter-cpp")

# Auto-build cpp.so if missing, so that users don't need a manual build step.
if not os.path.exists(_CPP_SO_PATH):
    try:
        os.makedirs(os.path.dirname(_CPP_SO_PATH), exist_ok=True)
        logger.info(f"cpp.so not found, building tree-sitter C++ grammar to {_CPP_SO_PATH}")
        Language.build_library(_CPP_SO_PATH, [_CPP_GRAMMAR_DIR])
        logger.info("Successfully built cpp.so for tree-sitter C++.")
    except Exception as e:
        logger.error(f"Failed to build cpp.so for tree-sitter C++: {e}")

CPP_LANGUAGE = Language(_CPP_SO_PATH, "cpp")


class StaticAnalysisAgent:
    # dfg_generation_prompt = PromptTemplate(
    #     "As a C/C++ data flow graph analyzer, analyze the provided program and generate a JSON representation of its data flow graph (DFG). Focus on the listed variables.\n\n"
    #     "Instructions:\n"
    #     "1. Identify data dependencies between variables.\n"
    #     "2. Track variable modifications and uses.\n"
    #     "3. Include function calls that affect variable values.\n"
    #     "4. Represent each variable as a node.\n"
    #     "5. Use edges to show data flow between nodes.\n\n"
    #     "Program:\n{program}\n\n"
    #     "Variables:\n{variables}\n\n"
    #     "Provide only the JSON output without additional explanation."
    #     )
    dfg_generation_prompt = PromptTemplate(
        "As a C/C++ data flow graph analyzer, analyze the provided program and generate a JSON representation of its data flow graph (DFG). Focus on the listed variables.\n\n"
        "Instructions:\n"
        "1. Identify data dependencies between variables.\n"
        "2. Track variable modifications and uses.\n"
        "3. Include function calls that affect variable values.\n"
        "4. Represent each variable as a node.\n"
        "5. Use edges to show data flow between nodes.\n\n"
        "Program:\n{program}\n\n"
        "Variables:\n{variables}\n\n"
        "IMPORTANT: Return ONLY the JSON wrapped in ```json code block like this:\n"
        "```json\n"
        '{{"nodes": [...], "edges": [...]}}\n'
        "```\n"
        "Do not add any explanation or other text."
    )


    dfg_generation_prompt_with_memory = PromptTemplate(
        "As a C/C++ data flow graph analyzer, analyze the provided program and generate a JSON representation of its data flow graph (DFG). Focus on the listed variables.\n\n"
        "Instructions:\n"
        "1. Identify data dependencies between variables.\n"
        "2. Track variable modifications and uses.\n"
        "3. Include function calls that affect variable values.\n"
        "4. Represent each variable as a node.\n"
        "5. Use edges to show data flow between nodes.\n\n"
        "Program:\n{program}\n\n"
        "Variables:\n{variables}\n\n"
        "Provide only the JSON output without additional explanation."
        "Below is the historical context (ignore if empty):\n"
        "Start\n"
        "{context_memory}\n"
        "End\n"
        )
    
    def __init__(self, llm, llm_embedding, use_memory=False):

        self.llm = llm
        self.parser=Parser()
        self.parser.set_language(CPP_LANGUAGE)
        self.chat_memory_buffer = ChatMemoryBuffer.from_defaults(llm=llm)
        self.vector_memory = VectorMemory.from_defaults(
            vector_store=None,  # leave as None to use default in-memory vector store
            embed_model=llm_embedding,
            retriever_kwargs={"similarity_top_k": 1},
        )
        self.composable_memory = SimpleComposableMemory.from_defaults(
            primary_memory=self.chat_memory_buffer,
            secondary_memory_sources=[self.vector_memory],
        )
        self.use_memory = use_memory
        
    def clean_comments(self, source_code):
        """
        Remove C++ comments (both single-line and multi-line) from the source code.
        """
        # Define regex patterns for single-line and multi-line comments
        single_line_comment_pattern = r'//.*?$'
        multi_line_comment_pattern = r'/\*.*?\*/'
        
        # Combine both patterns
        combined_pattern = f'({single_line_comment_pattern})|({multi_line_comment_pattern})'
        
        # Remove comments using re.sub
        cleaned_code = re.sub(combined_pattern, '', source_code, flags=re.DOTALL | re.MULTILINE)
        
        return cleaned_code
    
    def extract_variables(self, source_code):
        
        declarations = []
        tree=self.parser.parse(bytes(source_code, "utf8"))
        node=tree.root_node

        def get_text(node):
            """Helper function to get text from a node."""
            return source_code[node.start_byte:node.end_byte]

        def traverse(node):
            if node.type == 'declaration':
                type_node = node.child_by_field_name('type')
                if type_node is not None:
                    var_type = get_text(type_node)
                    for child in node.children:
                        if child.type=='identifier':
                            var_name = get_text(child)
                            declarations.append(var_type+' '+var_name)
                        else:
                            declarator = child.child_by_field_name('declarator') 
                            if declarator is not None:
                                var_name = get_text(declarator)
                                if 'pointer_declarator' in [c.type for c in declarator.children] or child.type=='pointer_declarator':
                                    declarations.append(var_type+'*'+var_name)
                                else:
                                    declarations.append(var_type+' '+var_name)

                # Traverse children
            for child in node.children:
                traverse(child)

        traverse(node)
        return declarations
    
    # def dfg_analysis(self, source_code):
        source_code=self.clean_comments(source_code)
        var_list=self.extract_variables(source_code)
        question = self.dfg_generation_prompt.format(program=source_code,variables=var_list)
        if self.use_memory and len(self.composable_memory.get_all()):
            context_memory = self.composable_memory.get(question)
            question = self.dfg_generation_prompt_with_memory(context_memory=context_memory,program=source_code,variables=var_list)
        dfg=self.llm.complete(question).text
        msgs = [
            ChatMessage.from_str(question, "user"),
            ChatMessage.from_str(dfg, "assistant")
        ]
        self.composable_memory.put_messages(msgs)
        
        pattern = r'```json\n(.*?)\n```'
        match = re.search(pattern, dfg, re.DOTALL)
        if match:
            json_data = match.group(1)
            # 打印提取的JSON数据
        
        else:
            json_data="No JSON data found."
        logger.info(f"DFG: {json_data}")

        return json_data
    def dfg_analysis(self, source_code):
        source_code=self.clean_comments(source_code)
        var_list=self.extract_variables(source_code)
        question = self.dfg_generation_prompt.format(program=source_code,variables=var_list)
        if self.use_memory and len(self.composable_memory.get_all()):
            context_memory = self.composable_memory.get(question)
            question = self.dfg_generation_prompt_with_memory(context_memory=context_memory,program=source_code,variables=var_list)
        dfg=self.llm.complete(question).text
        
        # ← 添加调试日志：看 LLM 实际返回了什么
        logger.debug(f"LLM raw response: {dfg[:200]}...")  # 只记录前200字
        
        msgs = [
            ChatMessage.from_str(question, "user"),
            ChatMessage.from_str(dfg, "assistant")
        ]
        self.composable_memory.put_messages(msgs)
        
        # ← 改进正则匹配：支持多种格式
        json_data = "No JSON data found."
        
        # 尝试格式1：```json ... ```（标准格式）
        pattern1 = r'```json\s*(.*?)\s*```'
        match = re.search(pattern1, dfg, re.DOTALL)
        if match:
            json_data = match.group(1).strip()
        
        # 尝试格式2：``` ... ```（没有 json 标签）
        if json_data == "No JSON data found.":
            pattern2 = r'```\s*(.*?)\s*```'
            match = re.search(pattern2, dfg, re.DOTALL)
            if match:
                json_data = match.group(1).strip()
        
        # 尝试格式3：直接 JSON（没有代码块）
        if json_data == "No JSON data found.":
            try:
                json.loads(dfg.strip())
                json_data = dfg.strip()
            except:
                pass
        
        logger.info(f"DFG: {json_data}")
        return json_data    
    

if __name__ == "__main__":

    dir="/home/xuhanxiang/project/Really_Fuzzing_ForALL/oss-fuzz-modified/docker_shared/fuzz_driver/c-ares/fuzz_driver/syntax_pass_rag"
    with open(dir+"/fuzz_driver_deepseek_14.cpp", 'r', encoding='utf-8') as f:
        source_code = f.read()
    static_agent=StaticAnalysisAgent(source_code)
    declarations=static_agent.extract_variables()
    print(declarations)
    dfg=static_agent.dfg_analysis()
    print(dfg)


    # dir="/home/xuhanxiang/project/Really_Fuzzing_ForALL/oss-fuzz-modified/docker_shared/fuzz_driver/c-ares/fuzz_driver/syntax_pass_rag"
    # with open(dir+"/fuzz_driver_deepseek_14.cpp", 'r', encoding='utf-8') as f:
    #     source_code = f.read()
    # from models.llamindex_api import LLamaIndexOpenAIModel
    # from configs.llm_config import LLMConfig
    # llm_config = LLMConfig.from_yaml_file("fuzzing_agent_engine/yaml/deepseek.yaml")
    # llm_coder = LLamaIndexOpenAIModel("deepseek-chat", llm_config)
    # static_agent=Static_Analysis_Agent(source_code, llm_coder)
    # declarations=static_agent.extract_variables()
    # print(declarations)
    # dfg=static_agent.dfg_analysis()
    # print(dfg)