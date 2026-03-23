import sys
from pathlib import Path
import os
import re
from loguru import logger
from llama_index.core.prompts import PromptTemplate
from llama_index.core import Settings
from llama_index.core  import  ServiceContext
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core.postprocessor import SimilarityPostprocessor
from llama_index.core import get_response_synthesizer
from llama_index.core.memory import (
    VectorMemory,
    SimpleComposableMemory,
    ChatMemoryBuffer,
)
from llama_index.core.llms import ChatMessage
from llama_index.core.program import LLMTextCompletionProgram
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from crash.sanitizer_parser import parse_sanitizer_output, format_crash_summary
from crash.triage import triage_crash
from crash.locator import locate_crash_site, format_call_chain_for_llm
from crash.debugger import format_runtime_context_for_llm


# ---------------------------------------------------------------------------
# Prompt length control — prevent token overflow
# ---------------------------------------------------------------------------
_MAX_SECTION_CHARS = 5000   # ~1250 tokens per section
_MAX_TOTAL_PROMPT_CHARS = 40000  # ~10000 tokens total


def _truncate(text: str, max_chars: int = _MAX_SECTION_CHARS, label: str = "") -> str:
    """Truncate text to max_chars, appending a note if truncated."""
    if not text or len(text) <= max_chars:
        return text or ""
    truncated = text[:max_chars]
    note = f"\n\n... [{label} truncated: {len(text)} -> {max_chars} chars] ..."
    return truncated + note


# ---------------------------------------------------------------------------
# Pydantic models for structured LLM output
# ---------------------------------------------------------------------------

class CrashAnalysis(BaseModel):
    is_api_bug: bool
    crash_category: str


class EnhancedCrashAnalysis(BaseModel):
    is_api_bug: bool
    crash_category: str
    root_cause_type: str
    root_cause_location: str
    root_cause_trigger: str
    severity: str
    data_flow: List[str]
    fix_suggestion: str


# ---------------------------------------------------------------------------
# Enhanced prompt templates
# ---------------------------------------------------------------------------

_ENHANCED_CRASH_PROMPT = PromptTemplate(
    """You are a vulnerability analysis expert. Analyze the following crash from a fuzz testing campaign.

IMPORTANT: A rule-based pre-filter has already assessed this crash. Consider its conclusion carefully.

============================================================
SECTION 1: PRE-FILTER TRIAGE RESULT
============================================================
Triage label: {triage_label}
Triage confidence: {triage_confidence}
Evidence:
{triage_evidence}

============================================================
SECTION 2: STRUCTURED CRASH SUMMARY (deterministic parse)
============================================================
{structured_crash_summary}

============================================================
SECTION 3: PRECISE CODE LOCATION & CALL CHAIN CONTEXT
============================================================
{call_chain_context}

============================================================
SECTION 4: RUNTIME CONTEXT (from dynamic reproduction)
============================================================
{runtime_context}

============================================================
SECTION 5: FUZZ DRIVER SOURCE CODE
============================================================
{fuzz_driver}

============================================================
SECTION 6: TARGET API SOURCE CODE
============================================================
{api_info}

============================================================
SECTION 7: ERROR PATTERNS
============================================================
Fuzz driver error patterns:
{fuzz_driver_error_patterns}

API error patterns:
{api_error_patterns}

============================================================
SECTION 8: RELATED CWE VULNERABILITIES
============================================================
{related_cwe_vulnerabilities}

============================================================
RAW SANITIZER OUTPUT
============================================================
{raw_crash_info}

============================================================
ANALYSIS INSTRUCTIONS
============================================================
Based on ALL of the above information, provide a comprehensive analysis.

The pre-filter labeled this crash as "{triage_label}" with confidence {triage_confidence}.
If the pre-filter says "likely_driver_bug" or "noise", carefully examine whether the crash
is truly caused by the fuzz driver's improper API usage (e.g., passing uninitialized structs,
invalid parameters) rather than a real vulnerability in the target library.

Please determine:
1. **Is this an API bug?** (True = real vulnerability in the target library; False = fuzz driver quality issue)
2. **Root cause type**: e.g., null-pointer-dereference, heap-buffer-overflow, use-after-free, uninitialized-memory, integer-overflow, etc.
3. **Root cause location**: The specific file:line in the TARGET LIBRARY where the root cause exists
4. **Trigger condition**: What input/state triggers this vulnerability
5. **Data flow**: How does data flow from the fuzz driver input to the crash point? List key steps.
6. **Severity**: critical / high / medium / low
7. **Fix suggestion**: How should the code be fixed?
8. **Crash category**: One of: {init_crash}. If none fits, suggest a new category.

Provide your analysis in a structured format addressing each point above."""
)

_ENHANCED_EXTRACT_PROMPT = (
    "From the analysis below, extract the following fields into a structured format.\n\n"
    "Analysis:\n{raw_answer}\n\n"
    "Extract:\n"
    "- is_api_bug: bool (True if this is a real vulnerability in the target API)\n"
    "- crash_category: str (one of the standard categories or a new suggested one)\n"
    "- root_cause_type: str (e.g. 'null-pointer-dereference', 'heap-buffer-overflow')\n"
    "- root_cause_location: str (file:line, e.g. 'ares_init.c:428')\n"
    "- root_cause_trigger: str (what condition triggers this bug)\n"
    "- severity: str (one of: critical, high, medium, low)\n"
    "- data_flow: List[str] (key steps in the data flow path)\n"
    "- fix_suggestion: str (brief fix suggestion)\n"
)


class CrashAnalyzer:
    init_crash = [
        "Segment Violation", "Uninitialized Stack", "Integer Overflow",
        "Buffer Overflow", "Out of Memory", "Null Pointer Dereference",
        "Memory Leak", "File Descriptor Leak", "Misaligned Address",
        "Type Error Cast", "TimeOut", "Assertion Failure",
        "Use After Free", "Double Free", "Stack Overflow",
    ]

    # Keep the original prompt for backward compatibility
    crash_analyze_prompt = PromptTemplate(
     """You are a software analysis expert tasked with analyzing the root cause of a crash during fuzzing. You will be provided with the following information:

    1. Crash information from fuzz engine
    2. Source code of the crashing fuzz driver
    3. Source code of the project APIs used by the fuzz driver
    4. Potential error patterns extracted from both the fuzz driver and the API source code
    5. Related CWE vulnerabilities

    Crash information:
    {crash_info}

    Fuzz driver source code:
    {fuzz_driver}

    Fuzzed API source code:
    {api_info}

    Potential error patterns in fuzz driver:
    {fuzz_driver_error_patterns}

    Potential error patterns in API:
    {api_error_patterns}

    Related CWE vulnerabilities:
    {related_cwe_vulnerabilities}

    Based on this information, please determine whether the crash was caused by the fuzz driver code or by a bug in the project's API. Provide a comprehensive analysis including:

    1. Is this an API bug? (Return True if it's an API bug, False if it's a fuzz driver bug)
    2. The specific location in the code where the crash likely occurred
    3. Description of the variables involved in the crash
    4. Which potential error patterns are relevant to this crash
    5. Any violations of expected behavior based on your understanding of the code
    6. Which CWE vulnerabilities (if any) are relevant to this crash
    7. A detailed explanation of your reasoning
    8. Categorize the crash into one of the following categories: {init_crash}. If the crash doesn't fit into any of these categories, suggest a new category and explain why it's needed.

    If you believe the crash was caused by the fuzz driver:
    - Provide the relevant fuzz driver code snippet
    - Explain how the fuzz driver might be misusing the API

    If you believe the crash was caused by a bug in the project's API:
    - Provide the relevant API code snippet
    - Explain how the API might be failing to handle certain inputs or conditions

    Please structure your response to clearly address each of these points."""
    )

    def __init__(self, llm, llm_embedding, query_tools, api_src, use_memory=False):
        self.llm = llm
        self.llm_embedding = llm_embedding
        self.api_src = api_src
        self.query_tools = query_tools
        self.use_memory = use_memory
        self.init_crash = CrashAnalyzer.init_crash

        self.chat_memory_buffer = ChatMemoryBuffer.from_defaults(llm=llm)
        self.vector_memory = VectorMemory.from_defaults(
            vector_store=None,
            embed_model=llm_embedding,
            retriever_kwargs={"similarity_top_k": 1}
        )
        self.composable_memory = SimpleComposableMemory.from_defaults(
            primary_memory=self.chat_memory_buffer,
            secondary_memory_sources=[self.vector_memory]
        )

    def extract_potential_error_patterns(self, code):
        prompt = PromptTemplate(
            "Analyze the following code and identify potential error patterns or edge cases that could lead to crashes:\n\n{code}\n\nList the potential error patterns (Without any summary or advice for fixing the bugs):"
        )
        response = self.llm.complete(prompt.format(code=code))
        return response.text.split('\n')

    def query_cwe_vulnerabilities(self, crash_info):
        cwe_index = self.query_tools["cwe_index"]

        if len(crash_info) > 3000:
            summarize_prompt = PromptTemplate(
                "Summarize the following crash information, focusing on the key details that might be relevant to identifying CWE vulnerabilities:\n\n{crash_info}\n\nSummary:"
            )
            crash_info_summary = self.llm.complete(summarize_prompt.format(crash_info=crash_info)).text
        else:
            crash_info_summary = crash_info

        cwe_query = PromptTemplate(
            "Analyze the following crash information for potential CWE vulnerabilities:\n"
            "Crash information:\n{crash_info}\n\n"
            "Identify and list the most relevant CWE vulnerabilities that might be related to this crash."
        )
        Settings.llm = self.llm
        Settings.embed_model = self.llm_embedding

        question = cwe_query.format(crash_info=crash_info_summary)

        cwe_retriever = cwe_index.as_retriever(similarity_top_k=3)
        cwe_query_engine = RetrieverQueryEngine.from_args(
            retriever=cwe_retriever,
            node_postprocessors=[SimilarityPostprocessor(similarity_cutoff=0.7)],
            response_synthesizer=get_response_synthesizer(
                response_mode="compact",
                verbose=True
            ),
            verbose=True
        )

        cwe_response = cwe_query_engine.query(question)
        return cwe_response.response

    # ------------------------------------------------------------------
    # Original analyze_crash — kept for backward compatibility
    # ------------------------------------------------------------------
    def analyze_crash(self, crash_info, fuzz_driver_path, api_combine):
        with open(fuzz_driver_path, 'r') as file:
            fuzz_driver = file.read()

        api_info = ""
        for api in api_combine:
            if api in self.api_src:
                api_info += f"{api}:\n{self.api_src[api]}\n\n"
            else:
                api_info += f"{api}: Source code not available\n\n"

        fuzz_driver_error_patterns = self.extract_potential_error_patterns(fuzz_driver)
        api_error_patterns = self.extract_potential_error_patterns(api_info)
        related_cwe_vulnerabilities = self.query_cwe_vulnerabilities(crash_info)

        try:
            parsed = parse_sanitizer_output(crash_info or "")
            structured_summary = format_crash_summary(parsed)
        except Exception as e:
            structured_summary = f"[CRASH] parse_failed: {e}"
        crash_info_with_summary = f"{structured_summary}\n\n--- RAW SANITIZER OUTPUT ---\n{crash_info}"

        question = self.crash_analyze_prompt.format(
            crash_info=crash_info_with_summary,
            fuzz_driver=fuzz_driver,
            api_info=api_info,
            fuzz_driver_error_patterns="\n".join(fuzz_driver_error_patterns),
            api_error_patterns="\n".join(api_error_patterns),
            related_cwe_vulnerabilities=related_cwe_vulnerabilities,
            init_crash=", ".join(self.init_crash)
        )

        logger.info("Crash Analysis Question:")
        logger.info(question)

        response = self.llm.complete(question).text

        logger.info("Crash Analysis Response:")
        logger.info(response)

        response_format_program = LLMTextCompletionProgram.from_defaults(
            output_cls=CrashAnalysis,
            prompt_template_str=(
                "The input answer is:\n {raw_answer}\n. "
                "Please help me extract the bool value of the variable <is_api_bug> and the string value of <crash_category>.\n"
                "If a new crash category was suggested, include it in <crash_category>."
            ),
            llm=self.llm
        )
        analyze = response_format_program(raw_answer=response)
        is_api_bug = analyze.is_api_bug
        crash_category = analyze.crash_category

        if crash_category not in self.init_crash:
            self.init_crash.append(crash_category)
            logger.info(f"New crash category added: {crash_category}")

        if self.use_memory:
            query_answer = [
                ChatMessage.from_str(question, "user"),
                ChatMessage.from_str(response, "assistant"),
            ]
            self.composable_memory.put_messages(query_answer)

        return is_api_bug, crash_category, response

    # ------------------------------------------------------------------
    # Enhanced analyze_crash — uses full pipeline context
    # ------------------------------------------------------------------
    def analyze_crash_enhanced(
        self,
        crash_info: str,
        fuzz_driver_path: str,
        api_combine: list,
        *,
        triage_result: Optional[Dict[str, Any]] = None,
        location_result: Optional[Dict[str, Any]] = None,
        runtime_context: Optional[Dict[str, Any]] = None,
    ):
        """Enhanced crash analysis with triage, locator, and debugger context.

        Args:
            crash_info: Raw sanitizer output text
            fuzz_driver_path: Path to the fuzz driver source file
            api_combine: List of API function names used by the driver
            triage_result: Output of triage_crash() — pre-filter verdict
            location_result: Output of locate_crash_site() — code context
            runtime_context: Output of reproduce_with_gdb() — runtime state

        Returns:
            (is_api_bug, crash_category, analysis_text, enhanced_result_dict)
        """
        with open(fuzz_driver_path, 'r') as file:
            fuzz_driver = file.read()

        api_info = ""
        for api in api_combine:
            if api in self.api_src:
                api_info += f"{api}:\n{self.api_src[api]}\n\n"
            else:
                api_info += f"{api}: Source code not available\n\n"

        fuzz_driver_error_patterns = self.extract_potential_error_patterns(fuzz_driver)
        api_error_patterns = self.extract_potential_error_patterns(api_info)
        related_cwe_vulnerabilities = self.query_cwe_vulnerabilities(crash_info)

        # Build structured crash summary
        try:
            parsed = parse_sanitizer_output(crash_info or "")
            structured_summary = format_crash_summary(parsed)
        except Exception as e:
            structured_summary = f"[CRASH] parse_failed: {e}"
            parsed = {}

        # Build triage if not provided
        if triage_result is None:
            driver_basename = os.path.basename(fuzz_driver_path) if fuzz_driver_path else None
            triage_result = triage_crash(parsed, fuzz_driver_basename=driver_basename)

        # Build location context if not provided
        if location_result is None:
            driver_basename = os.path.basename(fuzz_driver_path) if fuzz_driver_path else None
            location_result = locate_crash_site(parsed, driver_basename=driver_basename)

        # Format triage evidence for prompt
        triage_evidence_lines = []
        for ev in (triage_result.get("evidences") or []):
            triage_evidence_lines.append(
                f"  - [{ev.get('evidence_type')}] {ev.get('rule_name')}: "
                f"{ev.get('description')} (confidence={ev.get('confidence')})"
            )
        triage_evidence_str = "\n".join(triage_evidence_lines) if triage_evidence_lines else "  (no specific evidence)"

        # Format call chain context
        call_chain_str = format_call_chain_for_llm(location_result, max_frames=5)

        # Format runtime context
        if runtime_context and runtime_context.get("reproduced"):
            runtime_str = format_runtime_context_for_llm(runtime_context)
        else:
            runtime_str = "[RUNTIME] Dynamic reproduction not available for this crash."

        # Truncate long sections to prevent token overflow
        fuzz_driver_t = _truncate(fuzz_driver, _MAX_SECTION_CHARS, "fuzz_driver")
        api_info_t = _truncate(api_info, _MAX_SECTION_CHARS * 2, "api_source")  # allow more for API
        raw_crash_t = _truncate(crash_info, _MAX_SECTION_CHARS, "raw_crash_info")
        cwe_t = _truncate(related_cwe_vulnerabilities, _MAX_SECTION_CHARS, "cwe_vulnerabilities")

        # Build the enhanced prompt
        question = _ENHANCED_CRASH_PROMPT.format(
            triage_label=triage_result.get("label", "unknown"),
            triage_confidence=triage_result.get("confidence", 0.0),
            triage_evidence=triage_evidence_str,
            structured_crash_summary=structured_summary,
            call_chain_context=call_chain_str,
            runtime_context=runtime_str,
            fuzz_driver=fuzz_driver_t,
            api_info=api_info_t,
            fuzz_driver_error_patterns="\n".join(fuzz_driver_error_patterns[:20]),
            api_error_patterns="\n".join(api_error_patterns[:20]),
            related_cwe_vulnerabilities=cwe_t,
            raw_crash_info=raw_crash_t,
            init_crash=", ".join(self.init_crash),
        )

        # Final safety net: truncate entire prompt
        if len(question) > _MAX_TOTAL_PROMPT_CHARS:
            logger.warning(f"Prompt too long ({len(question)} chars), truncating to {_MAX_TOTAL_PROMPT_CHARS}")
            question = question[:_MAX_TOTAL_PROMPT_CHARS] + "\n\n[PROMPT TRUNCATED]\nPlease analyze based on the information provided above."

        logger.info("Enhanced Crash Analysis Question (length=%d)", len(question))

        response = self.llm.complete(question).text

        logger.info("Enhanced Crash Analysis Response:")
        logger.info(response)

        # Extract structured fields
        enhanced_result = None
        try:
            extract_program = LLMTextCompletionProgram.from_defaults(
                output_cls=EnhancedCrashAnalysis,
                prompt_template_str=_ENHANCED_EXTRACT_PROMPT,
                llm=self.llm,
            )
            enhanced_result = extract_program(raw_answer=response)
        except Exception as e:
            logger.warning(f"Failed to extract enhanced structured output: {e}")

        # Fallback to basic extraction
        if enhanced_result is None:
            try:
                basic_program = LLMTextCompletionProgram.from_defaults(
                    output_cls=CrashAnalysis,
                    prompt_template_str=(
                        "The input answer is:\n {raw_answer}\n. "
                        "Please extract is_api_bug (bool) and crash_category (str)."
                    ),
                    llm=self.llm,
                )
                basic_result = basic_program(raw_answer=response)
                is_api_bug = basic_result.is_api_bug
                crash_category = basic_result.crash_category
            except Exception:
                is_api_bug = triage_result.get("label") == "likely_api_bug"
                crash_category = parsed.get("bug_type") or "Unknown"
        else:
            is_api_bug = enhanced_result.is_api_bug
            crash_category = enhanced_result.crash_category

        if crash_category not in self.init_crash:
            self.init_crash.append(crash_category)
            logger.info(f"New crash category added: {crash_category}")

        if self.use_memory:
            query_answer = [
                ChatMessage.from_str(question, "user"),
                ChatMessage.from_str(response, "assistant"),
            ]
            self.composable_memory.put_messages(query_answer)

        enhanced_dict = enhanced_result.dict() if enhanced_result else {
            "is_api_bug": is_api_bug,
            "crash_category": crash_category,
        }

        return is_api_bug, crash_category, response, enhanced_dict
