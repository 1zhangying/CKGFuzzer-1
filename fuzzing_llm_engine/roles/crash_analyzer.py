import sys
from pathlib import Path
import os
import re
import hashlib
import json
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
_MAX_TOTAL_PROMPT_CHARS = 100000  # keep full decision rules when model context allows
_ENGINE_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _ENGINE_ROOT.parent


def _truncate(text: str, max_chars: int = _MAX_SECTION_CHARS, label: str = "") -> str:
    """Truncate text to max_chars, appending a note if truncated."""
    if not text or len(text) <= max_chars:
        return text or ""
    truncated = text[:max_chars]
    note = f"\n\n... [{label} truncated: {len(text)} -> {max_chars} chars] ..."
    return truncated + note


_CONTROL_CALL_NAMES = {"if", "for", "while", "switch", "return", "sizeof"}


def _find_likely_call_match(line: str) -> Optional[re.Match]:
    """Find the first real function call, skipping C/C++ control constructs."""
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(", line):
        if match.group(1) in _CONTROL_CALL_NAMES:
            continue
        return match
    return None


def _split_top_level_call_args(line: str) -> List[str]:
    """Best-effort split of a single C/C++ call's top-level arguments."""
    call_match = _find_likely_call_match(line)
    if call_match is None:
        return []

    open_pos = call_match.end() - 1
    args_chars: List[str] = []
    depth = 0
    for ch in line[open_pos + 1:]:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        args_chars.append(ch)
    args_src = "".join(args_chars)

    args: List[str] = []
    start = 0
    paren = 0
    bracket = 0
    brace = 0
    angle = 0
    for pos, ch in enumerate(args_src):
        if ch == "(":
            paren += 1
        elif ch == ")" and paren:
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]" and bracket:
            bracket -= 1
        elif ch == "{":
            brace += 1
        elif ch == "}" and brace:
            brace -= 1
        elif ch == "<":
            # Keep simple template/cast syntax from being split incorrectly.
            angle += 1
        elif ch == ">" and angle:
            angle -= 1
        elif ch == "," and paren == 0 and bracket == 0 and brace == 0 and angle == 0:
            args.append(args_src[start:pos].strip())
            start = pos + 1
    tail = args_src[start:].strip()
    if tail:
        args.append(tail)
    return args


def _call_has_explicit_length_after_fuzz_data(line: str) -> bool:
    """Return true for calls like api((const char *)data, len/10/sizeof(...)).

    This prevents pointer+explicit-length APIs from being mislabeled as raw
    C-string risks.  It is intentionally conservative for numeric constants:
    constants are treated as lengths only for APIs whose names suggest byte or
    buffer processing.
    """
    args = _split_top_level_call_args(line)
    if len(args) < 2:
        return False

    fn_match = _find_likely_call_match(line)
    fn_name = (fn_match.group(1) if fn_match else "").lower()
    length_capable_fn = bool(
        re.search(
            r"(?:mem|buf|byte|append|write|read|parse|load|decode|encode|process|copy|cmp|compare|scan|insert|add)",
            fn_name,
        )
    )

    length_name_re = re.compile(
        r"\b(?:len|length|size|count|nbytes?|bytes?|num|capacity|avail|remaining|limit)\b",
        re.IGNORECASE,
    )
    numeric_re = re.compile(r"^(?:0x[0-9a-fA-F]+|[1-9][0-9]*)(?:[uUlL]*)$")

    for pos, arg in enumerate(args):
        if "data" not in arg:
            continue
        for later in args[pos + 1:pos + 3]:
            cleaned = later.strip()
            if length_name_re.search(cleaned):
                return True
            if "sizeof" in cleaned or "std::min" in cleaned or "std::max" in cleaned:
                return True
            if re.search(r"\bdata\s*(?:\+|-)", cleaned) or re.search(r"(?:\+|-)\s*\bdata\b", cleaned):
                return True
            if length_capable_fn and numeric_re.match(cleaned):
                return True
    return False


def _collect_statement_from_line(lines: List[str], idx: int, max_lines: int = 12) -> str:
    """Collect a likely multi-line C/C++ statement starting at idx."""
    if idx < 0 or idx >= len(lines):
        return ""
    pieces = [lines[idx].strip()]
    paren_balance = pieces[0].count("(") - pieces[0].count(")")
    for next_idx in range(idx + 1, min(len(lines), idx + max_lines)):
        if ";" in pieces[-1] and paren_balance <= 0:
            break
        piece = lines[next_idx].strip()
        pieces.append(piece)
        paren_balance += piece.count("(") - piece.count(")")
        if ";" in piece and paren_balance <= 0:
            break
    return " ".join(piece for piece in pieces if piece)


def _is_archive_container_entry_api_call(call_text: str) -> bool:
    """Heuristic for archive/container entry/header creation APIs, not raw copy APIs."""
    fn_match = _find_likely_call_match(call_text)
    if fn_match is None:
        return False
    fn_name = fn_match.group(1).lower()

    archive_prefix = bool(re.search(r"(?:zip|archive|tar|jar|cab|cpio|minizip)", fn_name))
    entry_operation = bool(re.search(r"(?:open|new|create|add|write|put).*(?:file|entry|header|member)|(?:file|entry|header|member).*(?:open|new|create|add|write|put)", fn_name))
    simple_raw_api = bool(re.search(r"(?:compress|uncompress|deflate|inflate|read|memcpy|copy|fread|fwrite)$", fn_name))
    return archive_prefix and entry_operation and not simple_raw_api


def _call_has_extreme_metadata_pointer_length(call_text: str) -> bool:
    """Detect archive/container metadata pointer + extreme explicit length pairs."""
    if not _is_archive_container_entry_api_call(call_text):
        return False

    args = _split_top_level_call_args(call_text)
    if len(args) < 2:
        return False

    extreme_re = re.compile(r"\b(?:UINT_MAX|SIZE_MAX|INT_MAX|ULONG_MAX|0xffffffff|0xffff)\b")
    metadata_pointer_re = re.compile(
        r"\b(?:data|extra|extra_field|extrafield|comment|header|name|filename|metadata|field|global|local)\b",
        re.IGNORECASE,
    )
    for pos, arg in enumerate(args[:-1]):
        if not metadata_pointer_re.search(arg) or arg.strip() in {"nullptr", "NULL", "0"}:
            continue
        for later in args[pos + 1:pos + 3]:
            if extreme_re.search(later):
                return True
    return False


def _resolve_sanitizer_source_path(source_path: str) -> Optional[Path]:
    """Map sanitizer/container source paths such as /src/proj/file.c to host paths."""
    if not source_path:
        return None

    raw = Path(source_path)
    if raw.exists() and raw.is_file():
        return raw

    candidates: List[Path] = []
    normalized = source_path.replace("\\", "/")
    if normalized.startswith("/src/"):
        rel = Path(normalized[len("/src/"):])
        parts = rel.parts
        if parts:
            project = parts[0]
            candidates.extend(
                [
                    _ENGINE_ROOT / "build" / "out" / project / "src" / rel,
                    _REPO_ROOT / "fuzzing_llm_engine" / "build" / "out" / project / "src" / rel,
                    _REPO_ROOT / "code" / rel,
                    _REPO_ROOT / rel,
                ]
            )

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _format_source_lines(
    lines: List[str],
    *,
    start_idx: int,
    end_idx: int,
    highlight_idx: Optional[int] = None,
) -> str:
    start_idx = max(0, start_idx)
    end_idx = min(len(lines), end_idx)
    rendered = []
    for idx in range(start_idx, end_idx):
        prefix = ">>" if highlight_idx is not None and idx == highlight_idx else "  "
        rendered.append(f"{prefix} L{idx + 1}: {lines[idx].rstrip()}")
    return "\n".join(rendered)


def _extract_target_crash_source_context(
    parsed_crash: Dict[str, Any],
    *,
    driver_basename: Optional[str] = None,
    context_lines: int = 48,
) -> str:
    """Extract concrete target source around the first non-driver project frame."""
    frames = parsed_crash.get("frames") or []
    for frame in frames:
        source_path = frame.get("file") or ""
        func = frame.get("func") or "unknown"
        line_no = frame.get("line")
        if not source_path or not line_no:
            continue
        if driver_basename and driver_basename in os.path.basename(source_path):
            continue

        local_path = _resolve_sanitizer_source_path(source_path)
        if local_path is None:
            continue

        try:
            lines = local_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        crash_idx = max(0, int(line_no) - 1)
        sig_block = ""
        if func and func != "unknown":
            func_re = re.compile(rf"\b{re.escape(func)}\s*\(")
            sig_start = None
            for idx in range(crash_idx, max(-1, crash_idx - 260), -1):
                if func_re.search(lines[idx]):
                    sig_start = idx
                    break
            if sig_start is not None:
                sig_end = min(len(lines), sig_start + 12)
                for idx in range(sig_start, min(len(lines), sig_start + 40)):
                    if "{" in lines[idx]:
                        sig_end = idx + 1
                        break
                sig_block = (
                    f"Function signature / parameter context for {func}:\n"
                    + _format_source_lines(lines, start_idx=sig_start, end_idx=sig_end)
                    + "\n\n"
                )

        return (
            "TARGET CRASH SOURCE CONTEXT:\n"
            f"Sanitizer frame: {func} at {source_path}:{line_no}\n"
            f"Resolved host source: {local_path}\n"
            + sig_block
            + "Crash-line source context:\n"
            + _format_source_lines(
                lines,
                start_idx=crash_idx - context_lines,
                end_idx=crash_idx + context_lines + 1,
                highlight_idx=crash_idx,
            )
        )

    return "[TARGET SOURCE] Target crash source context unavailable."


def _extract_public_header_exposed_struct_context(
    parsed_crash: Dict[str, Any],
    fuzz_driver: str,
    *,
    driver_basename: Optional[str] = None,
) -> str:
    """Show whether mutated object fields are exposed by a public target header."""
    if not fuzz_driver:
        return "[PUBLIC HEADER] Fuzz driver source unavailable."

    include_names = re.findall(r'^\s*#\s*include\s+"([^"]+)"', fuzz_driver, flags=re.MULTILINE)
    if not include_names:
        return "[PUBLIC HEADER] No quoted target header include detected in fuzz driver."

    mutated_fields = sorted(
        {
            field
            for _, field in re.findall(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:->|\.)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=",
                fuzz_driver,
            )
        }
    )
    if not mutated_fields:
        return "[PUBLIC HEADER] No direct object-field mutation detected in fuzz driver."

    target_source_path = None
    for frame in parsed_crash.get("frames") or []:
        source_path = frame.get("file") or ""
        if driver_basename and driver_basename in os.path.basename(source_path):
            continue
        target_source_path = _resolve_sanitizer_source_path(source_path)
        if target_source_path is not None:
            break

    candidate_dirs: List[Path] = []
    if target_source_path is not None:
        candidate_dirs.extend([target_source_path.parent, target_source_path.parent.parent])

    for frame in parsed_crash.get("frames") or []:
        source_path = (frame.get("file") or "").replace("\\", "/")
        if source_path.startswith("/src/"):
            rel = Path(source_path[len("/src/"):])
            parts = rel.parts
            if parts:
                project = parts[0]
                candidate_dirs.extend(
                    [
                        _ENGINE_ROOT / "build" / "out" / project / "src" / project,
                        _ENGINE_ROOT / "build" / "out" / project / "src" / project / "include",
                        _ENGINE_ROOT / "external_database" / project / "fuzz_driver",
                        _REPO_ROOT / "code" / project,
                    ]
                )

    header_paths: List[Path] = []
    for include_name in include_names:
        include_path = Path(include_name)
        for base_dir in candidate_dirs:
            candidate = base_dir / include_path
            if candidate.exists() and candidate.is_file() and candidate not in header_paths:
                header_paths.append(candidate)
                break
        if len(header_paths) >= 4:
            break

    if not header_paths:
        return (
            "[PUBLIC HEADER] Quoted target headers were included by the driver, "
            "but the corresponding host header files could not be resolved."
        )

    field_re = re.compile(r"\b(?:" + "|".join(re.escape(field) for field in mutated_fields) + r")\b")
    blocks: List[str] = []
    for header_path in header_paths[:4]:
        try:
            lines = header_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        relevant_idxs = [
            idx
            for idx, line in enumerate(lines)
            if field_re.search(line)
            and ";" in line
            and "(" not in line
            and "->" not in line
            and "." not in line
            and "\\" not in line
            and not line.strip().startswith(("*", "//", "/*"))
        ]
        if not relevant_idxs:
            continue

        snippets: List[str] = []
        seen_ranges = set()
        for idx in relevant_idxs[:12]:
            struct_start = None
            for prev in range(idx, max(-1, idx - 40), -1):
                if re.search(r"\bstruct\b.*\{", lines[prev]):
                    struct_start = prev
                    break
            if struct_start is None:
                continue
            struct_end = None
            for nxt in range(idx, min(len(lines), idx + 80)):
                if re.search(r"^\s*}\s*[^;]*;", lines[nxt]):
                    struct_end = nxt + 1
                    break
            if struct_end is None:
                continue
            range_key = (struct_start, struct_end)
            if range_key in seen_ranges:
                continue
            seen_ranges.add(range_key)
            snippets.append(
                _format_source_lines(lines, start_idx=struct_start, end_idx=struct_end, highlight_idx=idx)
            )

        if not snippets:
            for idx in relevant_idxs[:3]:
                start = max(0, idx - 3)
                end = min(len(lines), idx + 4)
                snippets.append(_format_source_lines(lines, start_idx=start, end_idx=end, highlight_idx=idx))

        if snippets:
            blocks.append(
                f"Header {header_path} exposes mutated field(s): {', '.join(mutated_fields)}\n"
                + "\n...\n".join(snippets)
            )

    if not blocks:
        return (
            "[PUBLIC HEADER] Target headers were resolved, but the mutated field names "
            f"({', '.join(mutated_fields)}) were not found in those headers."
        )

    return (
        "PUBLIC HEADER / EXPOSED STRUCT CONTEXT:\n"
        "The fuzz driver mutates fields that are visible in a quoted target header. "
        "This is evidence for an exposed-object boundary-state test, not evidence of "
        "raw object fabrication by itself.  Treat soft documentation such as "
        "\"internal\", \"not recommended\", \"use wrapper\", \"check return code\", or "
        "\"caller is responsible\" as guidance, not as a concrete caller precondition "
        "forbidding field-boundary tests unless the header/API explicitly says callers "
        "must not modify the fields, the struct is opaque/private, or behavior is "
        "undefined when fields are changed.\n\n"
        + "\n\n".join(blocks[:3])
    )


def _filter_error_patterns_for_prompt(
    patterns: List[str],
    *,
    precondition_risk_context: str,
    source_kind: str,
) -> List[str]:
    """Remove LLM-generated pattern hypotheses contradicted by deterministic context."""
    cleaned = [pattern.strip() for pattern in patterns if pattern and pattern.strip()]

    if (
        source_kind == "fuzz_driver"
        and "Archive/container metadata length boundary candidate" in precondition_risk_context
    ):
        conflict_re = re.compile(
            r"(?:actual\s+(?:buffer|size)|buffer\s+(?:length|bounds)|claimed\s+length|"
            r"length\s+mismatch|size\s+mismatch|incorrect\s+size|should\s+(?:use|pass).*actual|"
            r"pass(?:ing)?\s+.*UINT_MAX.*(?:actual|buffer|length|size)|"
            r"UINT_MAX.*(?:actual|buffer|length|size))",
            re.IGNORECASE,
        )
        cleaned = [
            pattern
            for pattern in cleaned
            if not (
                conflict_re.search(pattern)
                and not re.search(
                    r"(?:archive|container|entry|header|extra[-_ ]?field|extrafield|comment|metadata|central|local)",
                    pattern,
                    re.IGNORECASE,
                )
            )
        ]

    return cleaned


def _fit_prompt_preserving_instructions(
    prompt_template: PromptTemplate,
    *,
    max_total_chars: int,
    required_instruction_text: str,
    logger_label: str = "prompt",
    **sections: Any,
) -> str:
    """Fit the prompt while preserving the final analysis instructions.

    The previous safety net truncated the whole prompt from the end.  That can
    remove the decision policy and JSON contract, which are more important than
    long source/CWE/raw sections for the current experiment.  This helper
    progressively shrinks evidence-heavy sections and only returns a prompt
    where the required instruction text is still present.
    """
    question = prompt_template.format(**sections)
    if len(question) <= max_total_chars:
        return question

    logger.warning(
        f"{logger_label} too long ({len(question)} chars), reducing evidence sections to preserve instructions"
    )

    shrink_order = [
        ("related_cwe_vulnerabilities", 1200),
        ("api_error_patterns", 1200),
        ("fuzz_driver_error_patterns", 1200),
        ("raw_crash_info", 1800),
        ("runtime_context", 2500),
        ("api_info", 7000),
        ("fuzz_driver", 6000),
        ("call_chain_context", 2500),
        ("driver_oracle_context", 2500),
        ("precondition_risk_context", 2500),
        ("decisive_evidence_context", 1800),
        ("triage_evidence", 1800),
    ]

    fitted = dict(sections)
    for key, cap in shrink_order:
        value = fitted.get(key)
        if isinstance(value, str) and len(value) > cap:
            fitted[key] = _truncate(value, cap, key)
            question = prompt_template.format(**fitted)
            if len(question) <= max_total_chars and required_instruction_text in question:
                return question

    if len(question) <= max_total_chars and required_instruction_text in question:
        return question

    # Last resort: preserve instructions by trimming only the largest evidence
    # sections further.  Never cut from the end of the full prompt.
    hard_caps = [
        ("api_info", 3500),
        ("fuzz_driver", 3500),
        ("raw_crash_info", 1000),
        ("runtime_context", 1200),
        ("call_chain_context", 1200),
        ("driver_oracle_context", 1200),
        ("precondition_risk_context", 1200),
        ("decisive_evidence_context", 900),
        ("related_cwe_vulnerabilities", 600),
        ("triage_evidence", 900),
        ("api_error_patterns", 600),
        ("fuzz_driver_error_patterns", 600),
    ]
    for key, cap in hard_caps:
        value = fitted.get(key)
        if isinstance(value, str) and len(value) > cap:
            fitted[key] = _truncate(value, cap, key)
    question = prompt_template.format(**fitted)

    if required_instruction_text not in question:
        logger.warning(f"{logger_label} fitting failed to preserve required instructions")
    if len(question) > max_total_chars:
        logger.warning(
            f"{logger_label} still long after fitting ({len(question)} chars); instructions preserved={required_instruction_text in question}"
        )
    return question


def _extract_decisive_evidence_context(
    *,
    structured_summary: str,
    call_chain_context: str,
    driver_oracle_context: str,
    precondition_risk_context: str,
    max_items: int = 10,
) -> str:
    """Build a compact, uniform evidence-audit section for every sample.

    This section deliberately does not use ground truth.  It summarizes the
    most decision-relevant evidence already extracted elsewhere so the model is
    forced to resolve concrete driver-misuse hypotheses before relying on
    target-stack location or generic robustness language.
    """
    pre = precondition_risk_context or ""
    chain = call_chain_context or ""
    oracle = driver_oracle_context or ""
    summary = structured_summary or ""

    negative_items: List[str] = []
    conditional_items: List[str] = []
    positive_guards: List[str] = []

    def add_once(items: List[str], text: str) -> None:
        if text and text not in items:
            items.append(text)

    risk_specs = [
        (
            "Manual target object fabrication risk",
            "manual target-object fabrication: verify whether malloc/calloc/stack/mock objects are passed to target cleanup/traversal/free APIs that require private target-created layout",
        ),
        (
            "Ownership-transfer failure-path risk",
            "ownership-transfer failure path: verify whether add/append/attach/insert/set_new consumed ownership before the driver also frees/decrefs/deletes the same object",
        ),
        (
            "Borrowed substring array risk",
            "borrowed C-string array: verify every pointer into fuzz-derived storage is independently NUL-terminated and live for no-length string APIs",
        ),
        (
            "No-length string API risk",
            "no-length C-string API: verify the exact pointer passed to strlen/hash/string traversal has guaranteed NUL termination and lifetime",
        ),
        (
            "Raw fuzz C-string risk",
            "raw fuzz C-string: verify the exact fuzz-derived char pointer is NUL-terminated before any no-length target API uses it",
        ),
        (
            "Post-parse error-state use risk",
            "post-parse error-state use: verify the driver does not continue print/insert/traversal on a failed parse or absent root state unless the API contract allows it",
        ),
        (
            "Unchecked state/status result risk",
            "unchecked state/status: verify stored init/config/reset/decode/open status is checked before later processing depends on that state",
        ),
        (
            "Direct object/stream metadata mutation risk",
            "direct stream/object metadata mutation: verify field writes create a valid public boundary-state test rather than an invalid protocol state",
        ),
    ]
    for marker, text in risk_specs:
        if marker in pre:
            add_once(negative_items, text)

    if "Stateful stream/reset/decode risk" in pre:
        # This broad risk appears in some true decoder/parser boundary tests, so
        # list it as a protocol item rather than a decisive negative unless
        # paired with a stronger unchecked/direct-mutation finding.
        target = negative_items if (
            "Unchecked state/status result risk" in pre or "Direct object/stream metadata mutation risk" in pre
        ) else conditional_items
        add_once(
            target,
            "stateful stream/reset/decode protocol: verify successful init/config and valid buffers are established before decode/process/reset-dependent operations",
        )

    if "Ownership/deallocator risk" in pre:
        crash_mentions_cleanup = re.search(
            r"\b(?:free|delete|decref|destroy|cleanup|use-after-free|double[- ]free|bad-free|destructor)\b",
            f"{summary}\n{chain}",
            re.IGNORECASE,
        )
        target = negative_items if crash_mentions_cleanup else conditional_items
        add_once(
            target,
            "cleanup/deallocator/lifetime: relevant only if the crash path is cleanup/destructor/free/use-after-free; verify allocator family, ownership transfer, and interior pointer lifetime",
        )

    if re.search(r"actually reads beyond the end of the string", chain, re.IGNORECASE) and re.search(
        r"\b(?:masked|masking trick|valgrind|word boundaries|hashlittle)\b",
        chain,
        re.IGNORECASE,
    ):
        add_once(
            negative_items,
            "sanitizer-only intentional word-at-a-time read: target source comments describe a masked overread; require separate semantic/write/corruption evidence before true attribution",
        )

    if "Target-created exposed object boundary-state candidate" in pre:
        add_once(
            positive_guards,
            "target-created exposed-object boundary candidate: do not reject solely for public field mutation if the object is live, target-created, and later passed to a public API that uses those fields",
        )

    if "Archive/container metadata length boundary candidate" in pre:
        add_once(
            positive_guards,
            "archive/container metadata boundary candidate: do not reduce this to raw pointer-size mismatch if a live archive handle and public entry/header metadata length are involved",
        )

    if "POST-CALL ORACLE DETECTED" in oracle:
        add_once(
            positive_guards,
            "post-call oracle candidate: if abort/assert is gated by target-produced return/state and checks a visible API invariant, analyze it as target evidence rather than final driver location",
        )

    lines = [
        "[DECISIVE-EVIDENCE] Uniform auto-generated audit candidates; no ground-truth labels are used.",
        "These items are inspection prompts, not negative evidence or labels. Their mere presence does not demonstrate driver misuse and must not by itself change the attribution. Resolve each applicable item against the actual crash path, driver source, target source, and visible contracts. Generic 'library should handle malformed input' language is not enough for either attribution.",
    ]
    if negative_items:
        lines.append("High-priority negative evidence to resolve:")
        for item in negative_items[:max_items]:
            lines.append(f"- {item}")
    else:
        lines.append("High-priority negative evidence to resolve: none detected by the generic scanner.")

    if conditional_items:
        lines.append("Conditional risks to audit without over-penalizing valid boundary tests:")
        for item in conditional_items[:max_items]:
            lines.append(f"- {item}")

    if positive_guards:
        lines.append("Positive guards to preserve recall when their exact conditions are met:")
        for item in positive_guards[:max_items]:
            lines.append(f"- {item}")

    return "\n".join(lines)


def _extract_driver_oracle_context(fuzz_driver: str, window: int = 12) -> str:
    """Extract source context around possible driver-side oracle sites.

    This is intentionally not ground truth.  It only highlights abort/assert-like
    driver checks so the model can distinguish an arbitrary harness failure from
    a driver-side oracle that reports a target API invariant violation.
    """
    if not fuzz_driver:
        return "[ORACLE] Fuzz driver source unavailable."

    lines = fuzz_driver.splitlines()
    oracle_markers = (
        "abort(",
        "assert(",
        "__builtin_trap(",
        "raise(SIGABRT",
        "raise(SIGTRAP",
    )
    call_pattern = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(")
    function_header_pattern = re.compile(
        r"^\s*(?:static\s+)?(?:extern\s+\"C\"\s+)?[A-Za-z_][A-Za-z0-9_:<>,\s\*&]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{"
    )
    control_prefixes = ("if", "for", "while", "switch", "return", "sizeof")

    blocks = []
    for idx, line in enumerate(lines):
        if not any(marker in line for marker in oracle_markers):
            continue

        start = max(0, idx - window)
        end = min(len(lines), idx + window + 1)
        context = []
        for lineno in range(start, end):
            prefix = ">>" if lineno == idx else "  "
            context.append(f"{prefix} L{lineno + 1}: {lines[lineno]}")

        preceding_calls = []
        for prev in range(max(0, idx - 25), idx):
            stripped = lines[prev].strip()
            if not stripped or stripped.startswith("//"):
                continue
            if stripped.startswith(control_prefixes):
                continue
            if call_pattern.search(stripped):
                preceding_calls.append(f"L{prev + 1}: {stripped}")

        enclosing_function = None
        for prev in range(idx, -1, -1):
            match = function_header_pattern.search(lines[prev])
            if match:
                enclosing_function = match.group(1)
                break

        callback_context = []
        if enclosing_function and enclosing_function not in {"LLVMFuzzerTestOneInput", "main"}:
            for lineno, src_line in enumerate(lines):
                if lineno == idx:
                    continue
                stripped = src_line.strip()
                if not stripped or stripped.startswith("//"):
                    continue
                if lineno <= idx and function_header_pattern.search(src_line):
                    continue
                if re.search(rf"\b{re.escape(enclosing_function)}\b", stripped):
                    callback_context.append(f"L{lineno + 1}: {stripped}")

            callback_keywords = (
                "Set",
                "Handler",
                "Callback",
                "Parse",
                "Decode",
                "Process",
                "Read",
                "Run",
                "Execute",
            )
            for lineno, src_line in enumerate(lines):
                stripped = src_line.strip()
                if not stripped or stripped.startswith("//"):
                    continue
                if any(keyword in stripped for keyword in callback_keywords) and call_pattern.search(stripped):
                    entry = f"L{lineno + 1}: {stripped}"
                    if entry not in callback_context:
                        callback_context.append(entry)

        blocks.append(
            "Candidate driver-side oracle/assertion site:\n"
            + "\n".join(context)
            + "\nOracle interpretation hint: this is a post-call driver check, not a standalone harness crash.\n"
            + "\nPotential preceding calls that may influence the oracle:\n"
            + ("\n".join(preceding_calls[-8:]) if preceding_calls else "  none detected")
            + "\nLikely causal chain:\n"
            + (
                "  "
                + " -> ".join(
                    re.sub(r"\(.*$", "", call.split(":", 1)[1].strip())
                    for call in preceding_calls[-3:]
                )
                + " -> abort()/assert()/trap()"
                if preceding_calls
                else "  none detected"
            )
            + (
                "\nRegistered callback / target-driven callback context:\n"
                + "\n".join(callback_context[-12:])
                + "\nCallback interpretation hint: when abort/assert/trap occurs inside a function registered as a target callback/handler, the callback arguments are target-produced output state. Inspect whether the predicate checks a target parser/decoder/handler invariant before treating it as harness-local."
                if callback_context
                else ""
            )
        )

    if not blocks:
        return "[ORACLE] No abort/assert/trap site detected in fuzz driver source."

    return (
        "POST-CALL ORACLE DETECTED:\n"
        "This is a driver-side reporting mechanism triggered after a target API call.\n"
        "Do not decide from the final abort/assert/trap location alone.  Trace the "
        "predicate back to the target API result/state and decide whether that predicate "
        "is a real API contract/invariant or only a harness-local expectation.\n\n"
        "If the preceding target call is a lookup/selection/path/key/index API and it "
        "returns success/non-null before the oracle rejects the selector syntax, this is "
        "a candidate target unexpected-acceptance signal only when the selector is a "
        "structured grammar/path/key/index interpreted by the target API and the rejected "
        "shape conflicts with that API-level selector semantics.\n\n"
        + "\n\n".join(blocks[:5])
    )


def _extract_precondition_risk_context(fuzz_driver: str, window: int = 4) -> str:
    """Highlight likely caller-precondition risks in the fuzz driver.

    This is deterministic context for the LLM, not a decision rule and not
    ground truth.  The goal is to make concrete driver-side risks visible near
    the final prompt so target-stack crashes are not over-attributed to the
    target merely because the relevant driver code is buried in a long source
    section.
    """
    if not fuzz_driver:
        return "[PRECONDITION] Fuzz driver source unavailable."

    lines = fuzz_driver.splitlines()
    findings = []
    seen = set()
    target_created_vars: Dict[str, str] = {}

    constructor_assign_re = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_:]*(?:new|New|create|Create|open|Open|parse|Parse|init|Init)[A-Za-z0-9_:]*)\s*\("
    )
    for src_line in lines:
        match = constructor_assign_re.search(src_line)
        if match:
            target_created_vars[match.group(1)] = match.group(2)

    def add(kind: str, idx: int, detail: str) -> None:
        key = (kind, idx)
        if key in seen:
            return
        seen.add(key)
        start = max(0, idx - window)
        end = min(len(lines), idx + window + 1)
        context = []
        for lineno in range(start, end):
            prefix = ">>" if lineno == idx else "  "
            context.append(f"{prefix} L{lineno + 1}: {lines[lineno]}")
        findings.append(f"{kind}: {detail}\n" + "\n".join(context))

    for idx, line in enumerate(lines):
        stripped = line.strip()
        lowered = stripped.lower()
        nearby = "\n".join(lines[idx:min(len(lines), idx + 5)]).lower()
        call_text = _collect_statement_from_line(lines, idx)

        if "ignore return value" in lowered or "suppress unused variable" in lowered:
            add(
                "Ignored return/status risk",
                idx,
                "driver explicitly ignores a return/status value that may guard initialization, configuration, parsing, reset, or decode state",
            )

        if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*(?:Init|Open|Create|Parse|Config|Configure|SetConfiguration|Reset|Seek|Decode|Process)[A-Za-z0-9_]*\s*\(", stripped):
            if any(token in nearby for token in ("ignore", "suppress unused", "(void)", "arbitrary", "raw fuzz", "from input data")):
                add(
                    "Stateful API protocol risk",
                    idx,
                    "stateful init/config/reset/decode/process call is near ignored status, arbitrary values, or fuzz-derived state",
                )

        result_assign = re.search(
            r"\b(?:int|char|unsigned\s+char|enum\s+[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_:<>*\\s]*?)\s+"
            r"([A-Za-z_][A-Za-z0-9_]*(?:result|status|error|rc)[A-Za-z0-9_]*)\s*=\s*"
            r"([A-Za-z_][A-Za-z0-9_:]*(?:Init|Open|Create|Parse|Config|Configure|SetConfiguration|Reset|Seek|Decode|Process|deflate|inflate)[A-Za-z0-9_:]*)\s*\(",
            stripped,
        )
        if result_assign:
            result_var, callee = result_assign.group(1), result_assign.group(2)
            following = "\n".join(lines[idx + 1:min(len(lines), idx + 16)])
            if (
                re.search(rf"\(void\)\s*{re.escape(result_var)}\b", following)
                or "Suppress unused" in following
                or not re.search(rf"\b(?:if|while)\s*\([^)]*\b{re.escape(result_var)}\b", following)
            ):
                add(
                    "Unchecked state/status result risk",
                    idx,
                    f"driver stores {callee} status in {result_var} but does not visibly gate later stateful processing on successful status",
                )

        if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*(?:Reset|PostSeek|SetConfiguration|Configure|Decode2?|deflate|inflate)[A-Za-z0-9_]*\s*\(", stripped):
            if any(token in lowered for token in ("reset", "setconfiguration", "postseek", "decode", "deflate", "inflate")):
                add(
                    "Stateful stream/reset/decode risk",
                    idx,
                    "driver uses reset/configuration/decode/stream processing; audit whether required successful init/config and buffer state are established before processing",
                )

        if re.search(r"\.[A-Za-z_]*(?:next_in|avail_in|next_out|avail_out|size|pos|capacity|offset|len|length)\s*=", stripped):
            add(
                "Direct object/stream metadata mutation risk",
                idx,
                "driver directly mutates public-looking object or stream metadata; audit whether this is a valid boundary-state test or an invalid protocol state",
            )

        for obj_var, ctor_name in target_created_vars.items():
            if not re.search(
                rf"\b{re.escape(obj_var)}\s*(?:->|\.)\s*(?:next_in|avail_in|next_out|avail_out|bpos|pos|position|size|capacity|cap|offset|len|length|used|alloc|end)\s*=",
                stripped,
            ):
                continue
            later_src = "\n".join(lines[idx + 1:min(len(lines), idx + 10)])
            target_call_re = re.compile(
                rf"\b(?!.*(?:free|Free|destroy|Destroy|delete|Delete))"
                rf"[A-Za-z_][A-Za-z0-9_:]*\s*\([^;\n]*\b{re.escape(obj_var)}\b",
            )
            if target_call_re.search(later_src):
                add(
                    "Target-created exposed object boundary-state candidate",
                    idx,
                    f"{obj_var} was returned by {ctor_name} and then exposed metadata is mutated before a later public API call on the same live object; this is not a caller-precondition violation by itself unless the object is fabricated, freed, mismatched, or passed to the wrong deallocator family",
                )

        if re.search(r"\bstruct\s+[A-Za-z_][A-Za-z0-9_]*\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\([^)]*struct\s+[A-Za-z_][A-Za-z0-9_]*\s*\*\s*\)\s*(?:calloc|malloc)\s*\(", stripped):
            if any(token in nearby for token in ("mock", "dummy", "simulate", "manual", "fabricat", "trigger real cleanup", "freeaddrinfo", "destroy", "cleanup")):
                add(
                    "Manual target object fabrication risk",
                    idx,
                    "driver allocates a target-looking struct with calloc/malloc instead of obtaining it from the matching target constructor; cleanup/traversal APIs may require private internal layout",
                )

        if re.search(r"\b[A-Za-z_][A-Za-z0-9_:]*(?:set_new|append_new|additem|AddItem|attach|Attach|insert|Insert)[A-Za-z0-9_:]*\s*\(", stripped):
            surrounding = "\n".join(lines[max(0, idx - 4):min(len(lines), idx + 8)])
            if re.search(r"(?:!=\s*0|==\s*0|!\s*[A-Za-z_][A-Za-z0-9_]*|failed|fail)", surrounding, re.IGNORECASE) and re.search(
                r"\b(?:free|Free|delete|Delete|decref|Decref|destroy|Destroy)\b", surrounding
            ):
                add(
                    "Ownership-transfer failure-path risk",
                    idx,
                    "driver calls an add/append/insert/set API with ownership-transfer semantics and then frees/decrefs/deletes on a failure path; audit whether ownership was already transferred or consumed",
                )

        if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]\s*=\s*&?[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]", stripped):
            following = "\n".join(lines[idx + 1:min(len(lines), idx + 40)])
            if re.search(r"\b[A-Za-z_][A-Za-z0-9_:]*(?:StringArray|CreateStringArray|SetString|set_string)[A-Za-z0-9_:]*\s*\(", following):
                add(
                    "Borrowed substring array risk",
                    idx,
                    "driver builds an array of C-string pointers into a fuzz-derived buffer; audit whether every pointed substring is independently NUL-terminated and live for a no-length string API",
                )

        if re.search(r"\b[A-Za-z_][A-Za-z0-9_:.]*(?:Parse|parse)\s*\(", stripped):
            following = "\n".join(lines[idx + 1:min(len(lines), idx + 40)])
            if re.search(r"(?:parse failed|parsing failed|even if .*failed|no root).*?(?:Print|InsertEndChild|Clear|FirstChild|RootElement)", following, re.IGNORECASE | re.DOTALL):
                add(
                    "Post-parse error-state use risk",
                    idx,
                    "driver continues document/object operations after parse failure or absent root state; audit whether later print/insert/traversal is a valid API sequence",
                )

        if _find_likely_call_match(stripped) is not None and _call_has_extreme_metadata_pointer_length(call_text):
            add(
                "Archive/container metadata length boundary candidate",
                idx,
                "public archive/container entry API receives metadata bytes plus an extreme metadata length/count (for example extra field, comment, header, filename, or entry metadata); this is a format-level boundary-value candidate, not ordinary raw-buffer length misuse, unless the API is a simple raw read/copy/compress function or the pointer/handle is invalid",
            )

        if (
            re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(.*(?:const\s+char\s*\*\)|reinterpret_cast\s*<\s*const\s+char\s*\*>).*data\s*(?:\+|,|\))", stripped)
            and not _call_has_explicit_length_after_fuzz_data(stripped)
        ):
            add(
                "Raw fuzz C-string risk",
                idx,
                "driver passes raw fuzz bytes as a C string; audit NUL termination, lifetime, and whether the API has an explicit length parameter",
            )

        if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*(?:set_string|SetString|set_name|SetName|set_key|SetKey|set_comment|SetComment)[A-Za-z0-9_]*\s*\(", stripped):
            if "data" in stripped and "char" in stripped:
                add(
                    "No-length string API risk",
                    idx,
                    "string/name/key/comment setter receives fuzz-derived char pointer; audit whether the driver guarantees NUL termination",
                )

        if re.search(r"\b[A-Za-z_][A-Za-z0-9_:]*(?:CreateString|StringArray|set_string|SetString|strdup|hash|Hash)[A-Za-z0-9_:]*\s*\(", stripped):
            if re.search(r"(?:data\s*\+|reinterpret_cast\s*<\s*const\s+char\s*\*>|const\s+char\s*\*)", stripped) and not _call_has_explicit_length_after_fuzz_data(stripped):
                add(
                    "No-length string API risk",
                    idx,
                    "ordinary C-string/string-array/hash API receives fuzz-derived char pointer without an explicit length argument; audit NUL termination and lifetime for the exact pointer passed",
                )

        if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*(?:free|Free|destroy|Destroy|delete|Delete)[A-Za-z0-9_]*\s*\(", stripped):
            add(
                "Ownership/deallocator risk",
                idx,
                "cleanup/deallocator/destructor call; audit matching allocator family, ownership transfer, and expected internal object layout",
            )

        if "data +" in stripped and re.search(r"\b(?:sizeof|UINT_MAX|SIZE_MAX|INT_MAX|\*\s*\d+|\+\s*\d+|- \s*\d+)", stripped):
            add(
                "Pointer/length consistency risk",
                idx,
                "driver derives a pointer into the fuzz buffer near arithmetic or constant sizes; audit whether any later length/count overstates readable bytes",
            )

    if not findings:
        return "[PRECONDITION] No obvious caller-precondition risk pattern detected by the lightweight source scan."

    return (
        "[PRECONDITION] Lightweight source scan lists possible caller-precondition checks below. "
        "They are candidate checks, not findings, ground truth, or negative labels. "
        "A listed pattern demonstrates driver evidence only when the actual driver code and the exposed or visible API contract establish the concrete violation on the crash path; pattern presence alone must not produce a false attribution. "
        "Conversely, do not infer target tolerance from generic robustness language when the concrete caller violation is visible. "
        "A cleanup/deallocator risk is relevant only when the crash happens during cleanup/deallocator/destructor processing or the cleanup call is on the causal path; ignore normal cleanup that appears after an already-reported post-call oracle.\n\n"
        + "\n\n".join(findings[:18])
    )


def _format_triage_evidence_for_prompt(ev: Dict[str, Any]) -> str:
    """Format stored triage evidence without preserving stale misleading wording.

    Historical crash_analysis.yaml records may contain descriptions generated by
    older triage rules.  In particular, driver_dominant_stack used to say the
    crash was "most likely caused by the driver itself", which is too strong for
    driver-side post-call oracle crashes.  Keep the rule identity/confidence, but
    normalize the wording before it reaches the LLM prompt.
    """
    rule_name = ev.get("rule_name")
    evidence_type = ev.get("evidence_type")
    description = ev.get("description")

    if rule_name == "driver_dominant_stack":
        evidence_type = "driver_location"
        description = (
            "Driver frames dominate the non-runtime stack, so the immediate "
            "crash report is driver-side. This is location evidence only: it "
            "may indicate a fuzz-driver issue, but it may also be a post-call "
            "oracle after a target API call. Do not treat this rule as root-cause "
            "evidence when an abort/assert/trap is gated by target API return "
            "value, lookup result, or target-owned state."
        )
    elif rule_name == "shallow_api_call":
        description = (
            "The crash occurs in or near a public API reached directly from the driver. "
            "This is a caller-precondition audit hint only, not root-cause evidence. "
            "Inspect the actual arguments and API role: direct calls to public parser, "
            "container, entry/header, or boundary-value APIs can be valid target tests."
        )
    elif rule_name == "raw_struct_memcpy_pattern":
        description = (
            "Historical heuristic name for possible raw-structure fabrication. "
            "Treat it as driver evidence only if the supplied fuzz-driver source "
            "actually shows raw struct memcpy, stack/mock object fabrication, "
            "or incompatible casting into a target object.  Ignore this hint when "
            "the driver merely passes bytes or metadata parameters to a public API."
        )
    elif rule_name == "assertion_failure":
        description = (
            f"{description} Assertion/abort/ABRT is not by itself driver-root-cause "
            "evidence; inspect whether it is a post-call oracle for target API "
            "behavior."
        )

    return (
        f"  - [{evidence_type}] {rule_name}: "
        f"{description} (confidence={ev.get('confidence')})"
    )


# ---------------------------------------------------------------------------
# Pydantic models for structured LLM output
# ---------------------------------------------------------------------------

class CrashAnalysis(BaseModel):
    is_api_bug: bool
    crash_category: str


class EnhancedCrashAnalysis(BaseModel):
    caller_precondition_verdict: str = "unclear"
    precondition_violations: List[str] = []
    tolerance_contract_evidence: str = ""
    driver_misuse_evidence_strength: str = "unclear"
    driver_misuse_location: Optional[str] = ""
    target_surface_evidence: Optional[str] = ""
    is_api_bug: bool
    crash_category: str
    root_cause_type: str
    root_cause_location: str
    root_cause_trigger: str
    severity: str
    data_flow: List[str]
    fix_suggestion: str
    confidence: float = 0.0
    decision_basis: str = "unknown"
    evidence_summary: str = ""


# ---------------------------------------------------------------------------
# Enhanced prompt templates
# ---------------------------------------------------------------------------

_ENHANCED_CRASH_PROMPT = PromptTemplate(
    """You are a vulnerability analysis expert. Analyze the following crash from a fuzz testing campaign.

Your task is to independently determine whether this crash reveals a real vulnerability in the target library API, or is caused by incorrect usage in the fuzz driver. Use ALL available evidence below to form your own judgment.

============================================================
SECTION 1: STATIC ANALYSIS OBSERVATIONS (reference only)
============================================================
Preliminary classification: {triage_label} (confidence: {triage_confidence})
Observations:
{triage_evidence}

NOTE: The above is an automated heuristic assessment. It may be wrong. You must verify independently using the crash details, source code, and runtime context below.
The preliminary label is routing/context only, not ground truth and not positive evidence. In particular, a "likely_api_bug" triage label must not override driver-misuse, wrong-deallocator, ownership-transfer, invalid-lifetime, or invalid-call-sequence evidence.

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
SECTION 5B: DRIVER ORACLE / ASSERTION CONTEXT
============================================================
{driver_oracle_context}

============================================================
SECTION 5C: CALLER PRECONDITION RISK CONTEXT
============================================================
{precondition_risk_context}

============================================================
SECTION 5D: DECISIVE EVIDENCE AUDIT (uniform, no ground truth)
============================================================
{decisive_evidence_context}

============================================================
SECTION 6: TARGET API SOURCE CODE
============================================================
{api_info}

============================================================
SECTION 7: ERROR PATTERNS
============================================================
The following lists are LLM-generated hypotheses from source snippets, not facts and not decision evidence by themselves.
Ignore any pattern that is contradicted by SECTION 5C, SECTION 5D, target crash source context, or the actual crashing call path.

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
{analysis_instructions}"""
)

_DIFFERENTIAL_DECISION_OUTPUT_CONTRACT = """
Return exactly one valid JSON object and no markdown or surrounding text. Use this schema:
{
  "caller_precondition_verdict": "valid|violated|unclear",
  "driver_misuse_evidence_strength": "hard|soft|none",
  "driver_misuse_location": "exact driver file:line and violated contract, or empty string",
  "target_surface_evidence": "the public target input/object/state that reaches the failing operation, or empty string",
  "precondition_violations": ["concrete caller-side violation, or empty list"],
  "tolerance_contract_evidence": "visible target API contract requiring tolerance of the listed violation, or empty string",
  "is_api_bug": true,
  "crash_category": "string",
  "root_cause_type": "string",
  "root_cause_location": "file:line, unknown when unavailable",
  "root_cause_trigger": "string",
  "severity": "critical|high|medium|low|unknown",
  "data_flow": ["ordered key step"],
  "fix_suggestion": "string",
  "confidence": 0.0,
  "decision_basis": "target_evidence|driver_evidence|insufficient_evidence",
  "evidence_summary": "short explanation naming the decisive evidence"
}

Fill caller_precondition_verdict before deciding is_api_bug:
- "valid" means the driver satisfied the relevant handle/object/lifetime/string/length/state/environment preconditions for the crashing call path.
- "violated" means a concrete driver-side precondition violation or listed SECTION 5C risk explains the crash path.
- "unclear" means the supplied evidence is insufficient to decide that gate.
If caller_precondition_verdict is "violated" and tolerance_contract_evidence is empty, is_api_bug must be false and decision_basis must be "driver_evidence".
If you return is_api_bug=true while SECTION 5C lists a relevant risk, tolerance_contract_evidence must name the concrete visible API contract that requires the target to tolerate that exact caller behavior; generic robustness expectations are not enough.
If SECTION 5D lists high-priority negative evidence, do not return is_api_bug=true until you explicitly refute that item using concrete driver/source/runtime/API evidence or cite a visible target contract that requires tolerance of the exact behavior.  Treat SECTION 5D as an audit checklist, not as a label.
Do not invent a caller-precondition violation from the original fuzz source bytes after the driver has repaired that precondition before the target call.  In particular, a C-string/key/selector precondition is satisfied when the exact pointer passed to the target API is a local or allocated buffer and the driver explicitly writes a NUL terminator within that buffer before the call, such as buf[len] = '\0'.  In that case, do not mark caller_precondition_verdict as "violated" merely because the bytes originally came from fuzz input.
For post-call oracle crashes, apply the precondition gate only to preconditions that are actually violated on the target call path.  If the target object was validly constructed, the exact selector/key/string pointer passed to the target is NUL-terminated, and the abort is gated by the target API's success/non-null result, then analyze it as a possible target semantic oracle rather than a caller-precondition failure.
Do not mark caller_precondition_verdict as "violated" for a target-created exposed object boundary-state test.  If the object was returned by a matching target constructor/open/new/parse function and is then passed back to a public target API that accepts that object, direct mutation of exposed size/position/capacity/index metadata is a boundary-state test, not fabrication, unless the object was freed, mismatched, or not created by the target.
For target-created exposed-object boundary-state tests, caller_precondition_verdict must not be "violated" merely because the driver writes public/exposed metadata fields.  If a matching target constructor/open/new/parse API created the object and a public target API later accepts the same live object, treat the caller precondition as valid or unclear, not violated.  The absence of target API source code is not evidence that the object is fabricated or that field mutation is forbidden.  Return false only if the object was raw-allocated, cast into the target type, freed/closed, mismatched, or passed to the wrong deallocator family.
If SECTION 3 includes "PUBLIC HEADER / EXPOSED STRUCT CONTEXT" showing that the mutated fields are visible in a quoted target header, do not treat those field writes as raw-object corruption by themselves.  Soft documentation such as "internal", "direct use not recommended", "use a wrapper", "check the return code", or a static helper comment saying "caller is responsible for calculations" is not a concrete precondition forbidding boundary-state tests on a target-created live object.  It can reduce confidence, but caller_precondition_verdict should be "violated" only when the visible API/header explicitly says the fields are private/opaque, callers must not modify them, a specific invariant such as position <= size is a required caller precondition, or behavior is undefined after such mutation.
Do not mark caller_precondition_verdict as "violated" solely because a public file/source/URI/path API receives an existing, NUL-terminated path or URI whose contents, target type, or scheme-specific resource is malformed, unsupported, non-directory, or otherwise adversarial.  If the driver creates the resource or supplies a syntactically valid source string and the target then dereferences a NULL handle, DIR pointer, parser state, or resource descriptor instead of returning an error, treat this as a possible target validation failure.
Do not mark caller_precondition_verdict as "violated" solely because a public archive/container/format entry API receives an extreme explicit metadata length/count, such as an extra-field/comment/header/name/filename length.  When the archive/container handle is live and the length/count is part of entry/header metadata construction, this is a format-level boundary-value test; the target should reject impossible, truncating, overflow-inducing, or archive-format-invalid metadata lengths before header allocation, arithmetic, or metadata traversal.  The concrete target contract is not "the library can know the backing allocation size"; it is that archive/container metadata fields have target-visible format limits, header field widths, and arithmetic constraints that can be validated before reading the metadata pointer.  Treat it as a raw buffer-length lie only when the API is plainly a simple memory copy/read/compress function with no archive/container entry metadata context, or when the pointer/handle itself is invalid.
If SECTION 5C lists "Archive/container metadata length boundary candidate" and SECTION 3 target crash source context or SECTION 6 API source/signature shows metadata parameters such as extra-field, comment, header, filename/name, central/local header, or entry metadata, caller_precondition_verdict must not be "violated" merely because the metadata length is larger than the backing fuzz buffer.  In that narrow pattern, the relevant contract evidence is the public archive/container entry API plus target source using the length for header/metadata construction or fixed-width metadata fields; set caller_precondition_verdict to "valid" or "unclear" unless the archive handle is invalid, the metadata pointer is null when the API forbids it, or the function is a simple raw copy/read/compress API.

Set is_api_bug to true only when the target-component hypothesis is better supported after caller preconditions are checked.
Set it to false when driver behavior or another non-target explanation is better supported.
The absence of an exact target source line, unavailable dynamic reproduction, or incomplete symbols alone is not evidence of a driver bug. Record such gaps in decision_basis/evidence_summary and still make the best-supported binary decision.

Final precondition gate (apply immediately before choosing is_api_bug):
First ask whether the crashing target API was reached through valid caller preconditions.  If a concrete caller-side precondition violation is visible, it takes precedence over target-internal stack frames and over the general robustness idea that "libraries should handle malformed input".
Return is_api_bug=false when any of these gates match and no visible API contract explicitly requires the target to tolerate that exact misuse:
- wrong deallocator/free/delete/destructor family or wrong expected internal allocation layout;
- object/buffer fabricated by malloc/new/stack/memcpy/cast instead of the matching target constructor;
- ordinary C string/key/name/tag/comment/filename passed without guaranteed NUL termination to an API that has no explicit length parameter, followed by strlen/hash/string traversal overread;
- ownership-transfer APIs such as add/append/attach/insert/set_new where the driver frees/decrefs/deletes the child/value/key on a failure or cleanup path without proving the API did not consume ownership;
- sanitizer-only word-at-a-time hash/string overread where target source comments explicitly say it intentionally reads beyond the end of a string/key and masks the tail; do not call this a target vulnerability unless there is evidence of a real write, control-flow corruption, or contract-violating target output beyond the sanitizer artifact;
- stateful codec/parser/compression stream used after ignored failed init/config/parse, arbitrary config/reset/seek, direct stream-field mutation, unchecked stored status/result, or reset followed by processing without re-establishing buffers and checking return codes;
- resolver/capture/device/file/environment API used with an unconfigured runtime resource, missing server/device/directory/interface, or fuzz-derived unsupported environment setting;
- raw pointer plus size/count pair where the driver claims more readable memory than the allocation actually provides, except for public archive/container entry metadata APIs where the same pair represents explicit extra-field/comment/header/name metadata and the crash is caused by failure to reject impossible format metadata before header construction or traversal.
If your own data_flow, evidence_summary, or fix_suggestion would say the fuzz driver should use a different deallocator, NUL-terminate a string, avoid fabricating an object, check initialization/configuration success, avoid arbitrary reset/configuration/stream reuse, supply valid environment resources, or pass a truthful buffer length, then the final answer must be is_api_bug=false unless you also cite a concrete visible target API contract requiring tolerance of that misuse.
Do not re-label a matched precondition violation as an "API design flaw", "documentation problem", or "missing defensive check" unless the supplied evidence contains the relevant contract text.  Without such contract evidence, it is driver_evidence.
This gate does not block true attribution for supported post-call/callback oracles, target-created exposed-object boundary-state tests, public archive/container entry metadata length boundary tests, or explicit public scalar length/count boundary tests when their positive conditions are met and none of the precondition violations above better explains the crash.
Positive exposed-object boundary state overrides the generic precondition gate: target-created live object + exposed metadata mutation + public target API arithmetic/memory crash is target evidence; do not call this fabricated object misuse solely because source code is unavailable or because the metadata value is extreme.
Positive exposed-object boundary state also overrides soft "not recommended/internal/helper caller responsible" documentation when the public header exposes the mutated fields and the crash is caused by the target API's unchecked arithmetic, overflow, extension, copy, or write based on those fields.  This override does not apply to opaque structs, fabricated malloc/stack/cast/memcpy objects, freed/mismatched objects, wrong deallocator family, cleanup-only crashes, or headers/API docs that explicitly forbid field mutation or declare the resulting behavior undefined.
Positive archive/container metadata boundary overrides the raw pointer+length gate only in its narrow form: live archive/container handle + public entry/header API + metadata pointer/length argument + target source/signature indicates extra-field/comment/header/name/entry metadata or fixed-width header fields + crash during header construction/arithmetic/traversal before rejecting impossible metadata.  In that case, do not write that the driver should pass the actual fuzz-input size unless the API is actually a simple raw read/copy/compress operation.
Final consistency check for archive/container metadata boundary:
If SECTION 5C lists "Archive/container metadata length boundary candidate" and you want to return caller_precondition_verdict="violated" or is_api_bug=false because "the metadata length exceeds the actual fuzz buffer size", you must first explicitly show that the crashing API is a simple raw copy/read/compress API, or that the archive handle/pointer is invalid, or that the visible API/header contract explicitly makes that exact metadata length a caller precondition.  If you cannot show one of those disqualifiers, that false reasoning is invalid: use caller_precondition_verdict="valid" or "unclear", set decision_basis="target_evidence", and decide the crash as the target failing to reject impossible archive/container entry metadata before header construction or metadata traversal.

Hard negative boundary rule:
Classify as is_api_bug=false when one or more of the following non-target explanations is better supported than the target-defect hypothesis:
1. the driver creates an invalid object, invalid call sequence, invalid lifetime, incompatible configuration, wrong allocator/free pair, out-of-contract pointer/buffer/size, or corrupted target structure before calling the target API;
2. the abort/assert/trap predicate is a harness-local filter, random predicate, artificial character ban, coverage/debug sentinel, resource limit, or policy choice not tied to a visible API contract/invariant;
3. the target API behavior shown in the evidence is explicitly permitted, best-effort, opaque-string based, prefix/partial matching based, fallback based, environment-dependent, or otherwise outside a strict semantic violation;
4. the crash is a timeout/hang/resource exhaustion that can be explained by normal blocking behavior, unconstrained fuzz workload, environment I/O, unsupported configuration, or missing progress bound rather than target abnormal non-progress;
5. the evidence is insufficient and the only positive signal is that a target function appears somewhere in the stack.
Target-internal sanitizer frames are positive evidence, but they are not decisive by themselves.  They can be outweighed by concrete driver-misuse evidence such as wrong deallocator, invalid ownership/lifetime, invalid object construction, or invalid call sequence.

Decisive driver-misuse boundary:
Classify as is_api_bug=false when the evidence shows one of these exact driver-originating causes and no visible API contract says the target must tolerate it:
1. NULL, uninitialized, failed-initialization, or already-closed target handles passed to APIs that expect a live handle;
2. calling a deallocator/free/delete/destructor that expects one allocation family or internal object layout on a buffer/object returned by a different API family or by ordinary malloc/new;
3. passing raw, stack, mock, shallow-copied, or manually fabricated objects into target cleanup/traversal/destructor functions;
4. passing a C string/key/comment/name to an API that expects a valid NUL-terminated string when the driver creates it from a fuzz slice without ensuring NUL termination and the failure is strlen/hash/string traversal reading past the allocation;
5. freeing/decrefing/deleting a value after an add/append/attach/insert/set_new call on a path where ownership may already have been transferred, consumed, or invalidated by the target API;
6. for stateful decoders/parsers, decoding after explicitly ignored failed initialization, decoding without any successful initialization gate, mutating decoder configuration/state fields from raw fuzz bytes, storing status/result and not using it to gate processing, or calling reset/seek/configuration APIs with arbitrary values before decode when that invalid state explains the crash;
7. timeout/hang caused by invalid device names, environment I/O, unsupported live capture/ring-buffer setup, or unconstrained blocking calls from the driver.
If the model's own data_flow or fix_suggestion says the driver should use a different deallocator, pass a live handle, NUL-terminate the string, avoid fabricating the object, check initialization success, or avoid arbitrary reset/configuration state, that is driver_evidence and should normally make is_api_bug=false.

Strict attribution threshold:
Do not classify as is_api_bug=true only because "the library should handle malformed input gracefully" or because the sanitizer top frame is inside target code.  That is a robustness expectation, not by itself target-component attribution.
For true attribution, identify a concrete target-side contract/invariant failure that remains after driver preconditions are satisfied.  Otherwise prefer false when the crash is better explained by invalid driver setup, invalid stateful API protocol, environment-dependent resources, or invalid C string/buffer preconditions.

Network/environment configuration boundary:
For resolver, packet-capture, file-discovery, device, interface, directory, or environment-dependent APIs, a non-NULL handle from an open/init call is not enough to prove valid API usage.  The driver must also provide required runtime configuration/resources such as configured servers, valid interface/device names, valid directories, event processing expectations, or supported URI schemes.
If the crash is caused by an empty/unconfigured runtime resource list, NULL environment-derived resource, non-existent device/directory, or unsupported live/system operation created from fuzz bytes, classify as false unless the API contract clearly promises to validate and reject that exact condition.
Exception: when the driver supplies an existing temporary file/path or a syntactically valid source URI to a public API that is responsible for parsing, opening, enumerating, or rejecting that source, malformed contents or an unsupported source kind are boundary inputs rather than caller-precondition violations.  If the target converts that boundary input into a NULL directory/resource/parser handle and then dereferences it, prefer target attribution.

Stateful stream/reset/decode protocol boundary:
For compression, decompression, codec, parser, or decoder streams, classify as false when the driver changes stream fields from raw fuzz data, calls reset/seek/configuration APIs at arbitrary times, ignores failed initialization/parse/configuration return values, or continues encode/decode after reset without re-establishing input/output buffers and checking return codes.
Do not treat the resulting target-internal read/null-deref as a target bug when it is better explained by a driver-created invalid stream state.  Classify as target only when the driver follows the documented init-configure-process-finish protocol or when the target-created state becomes invalid despite checked successful calls.

String/key/hash traversal boundary:
For APIs that take ordinary C strings, object keys, metadata strings, filenames, comments, tags, or names, the driver must provide a valid NUL-terminated string with a lifetime that covers the call unless the API explicitly accepts pointer+length data.
If the failure is strlen/hash/string traversal reading past an allocation, or a low-level word-at-a-time hash/read over a short key/string, classify as false when the key/string comes from a fuzzer slice or temporary buffer and the evidence does not show a pointer+length API contract or a target-created string object.
This boundary applies to the exact pointer passed into the target API.  Do not apply it when the driver first copies the fuzz slice into a bounded local/heap buffer and explicitly NUL-terminates that buffer before the call; in that case the C-string precondition is satisfied and any later post-call oracle should be judged on target API semantics.
Special sanitizer-artifact case: if the target source context itself says the hash/string routine intentionally reads beyond the end of a key/string and masks off the invalid tail, and the only failure is a sanitizer read report in that helper, classify false unless there is separate evidence of a real target semantic violation or memory write.  A known intentional word-at-a-time read is not enough for target vulnerability attribution by itself.
Do not convert this into true merely by saying the target should bounds-check the string; C string APIs may rely on NUL termination and valid lifetime as caller preconditions.

Ownership/deallocator boundary rule:
Target-internal sanitizer frames are not sufficient by themselves.  Before treating an internal free/delete/destructor/use-after-free/bad-free/double-free/buffer-overflow as a target bug, verify that the driver used the correct ownership protocol for the object or buffer.
Classify as is_api_bug=false when the evidence better supports any of these driver-side ownership mistakes:
1. passing an object/buffer to a target free/delete/destructor API that was not allocated or returned for that deallocator family;
2. mixing standard malloc/free/new/delete with target-owned allocators/deallocators or using a generic-looking target free function as if it freed all target outputs without visible contract support;
3. deleting/freeing a child object after an add/append/attach/insert/set operation that likely transferred ownership to a parent object, or deleting/freeing the parent and then continuing to use child pointers, keys, strings, iterators, or lookup results obtained from it;
4. using an object after any cleanup/delete/free/clear/release call that may invalidate it or invalidate interior pointers;
5. passing stack-allocated, manually fabricated, shallow-copied, already-freed, detached-without-ownership, or partially initialized structures into target cleanup/free/traversal APIs.
In these cases, even if the final ASan frame is inside the target library, the root cause is driver misuse unless the visible API contract says the target must tolerate that misuse.
Conversely, preserve target attribution when the object/buffer was produced by the matching target API, ownership has not been transferred or invalidated by the driver, and the crash occurs during ordinary target processing or cleanup.

Target-created exposed-object boundary-state rule:
Do not automatically classify a crash as driver misuse merely because the driver mutates fields of an object returned by a target constructor.  If the target library exposes the object's struct layout or otherwise lets callers pass the mutable object back to public target APIs, field mutations of size/position/capacity/index metadata can be boundary-state tests of the target API.
Classify as is_api_bug=true when all of the following hold:
1. the object was created by a matching target constructor/open/new API, not fabricated by raw allocation, memcpy, stack allocation, or incompatible casting;
2. the crash occurs inside a target API that accepts that object and performs arithmetic, bounds checks, growth, memcpy/memmove, or writes based on the object's metadata;
3. the target API fails to validate overflow, negative/huge positions, size-capacity consistency, or write bounds before the memory operation.
Classify as driver misuse instead when the object was fabricated, is the wrong concrete type, has the wrong allocation layout, is freed/closed, or is passed to a mismatched cleanup/deallocator family.
For this positive pattern, do not require a separate tolerance_contract_evidence string beyond the visible target constructor plus public target API accepting the same object.  The boundary-state evidence itself satisfies the precondition gate when the object is target-created and live.
The absence of target API source code does not negate this rule.  If the visible driver code shows a target constructor/open/new call returning the object and a later public target API receiving the same live object, do not infer forbidden field mutation or fabricated-object misuse from missing source alone.
If a public target header exposes the object's fields, a driver assignment to those fields is an exposed boundary-state input.  Do not equate it with fabricated-object misuse merely because target source comments call a lower-level helper "internal", recommend a faster wrapper, or say the helper caller is responsible for calculations.  Classify as driver misuse only when the object itself is not target-created/live, the field access is through an opaque/private type violation, or a visible hard contract explicitly requires the driver to maintain the exact invariant that was broken.

Extreme public length / boundary-value rule:
Do not automatically classify a crash as driver misuse merely because the driver passes an extreme scalar length/count such as UINT_MAX, SIZE_MAX, INT_MAX, or a near-overflow value into a public target API.  Such values are valid boundary tests when the API has an explicit length/count parameter and the target can reject impossible, protocol-invalid, or overflow-inducing lengths before copying/reading.
Classify as is_api_bug=true when the pointer/handle itself is live, the target API receives an explicit length/count field, and the target performs unchecked arithmetic or loops/copies/reads based on that public parameter instead of returning an error.
Classify as driver misuse when the driver lies about the size of a raw memory buffer in a simple pointer+length pair and the target has no other protocol or object-level way to validate the allocation extent.
For archive/container/format entry APIs, explicit lengths for extra fields, comments, headers, names, filenames, or entry metadata are protocol metadata boundary values, not merely raw allocation extents.  If such a length is impossible, truncating, or near-overflowing, target code should reject it before central/local header construction, internal arithmetic, descriptor construction, or metadata traversal; a crash there is target evidence when the archive handle and metadata pointer are live.  A C API cannot know the allocation extent behind an arbitrary pointer, so do not base true attribution on that.  Base it on visible format-level validation opportunities such as fixed-width metadata fields, maximum header sizes, central/local header construction, or overflow checks that must occur before copying/traversing metadata.  Do not collapse this pattern into raw pointer+length misuse unless the function is a simple raw read/copy/compress API rather than an archive/container entry/header API.

Driver-side oracle rule:
A crash whose immediate frame is in the fuzz driver is not automatically a driver bug.
If the driver calls a target API and then aborts/asserts/traps because the target API returned an unexpected value, accepted an invalid state, or violated an API-level invariant, treat the driver abort/assert/trap as an oracle signal and evaluate the target API behavior as the possible root cause.
For a post-call oracle, the decisive event is the target API producing or accepting the state that makes the driver-side oracle fire; the final abort/assert/trap line is only the reporting mechanism.
When the abort/assert/trap is gated by a target API return value, target object pointer, parsed state, lookup result, or semantic acceptance of a driver-supplied path/key/index, treat this as candidate target-component evidence.  It becomes decisive target evidence only when the checked predicate expresses a visible API contract, parser rule, data-structure invariant, bounds rule, ownership rule, or semantic consistency property.
If the driver performs a successful parse/lookup/transform and only then aborts on a property of the returned or derived state, compare two hypotheses: target semantic violation versus harness-local expectation.  Prefer target attribution when the predicate is semantically tied to the API behavior; prefer false when the predicate is merely an arbitrary harness condition.
Selector/path/key/index oracle rule:
For target APIs that parse, resolve, look up, select, retrieve, find, or get an element by a driver-supplied selector/path/key/index string, a non-null or success return may be semantic acceptance by the target API.
Classify this pattern as target unexpected-acceptance only when all of the following are better supported than the driver-misuse hypothesis:
1. the target object being queried was validly constructed or successfully parsed before the lookup/selection;
2. the selector/path/key/index is interpreted by the target API as a structured selector grammar, path grammar, object key/index rule, or structural query, not merely as an opaque arbitrary string;
3. the driver aborts only after the successful target lookup/selection and the rejected characters/token shape are tied to that selector/path/key/index grammar or object-structure invariant;
4. the evidence does not show that the API contract permits partial parsing, prefix matching, fallback lookup, opaque arbitrary keys, ignoring trailing invalid selector characters, or best-effort behavior.
In this pattern, the driver is checking whether the target API wrongly accepted a malformed structured selector/path/key/index.  If these conditions are met, classify as is_api_bug=true even though the final abort is in the fuzz driver.
Do not apply this selector/path/key/index rule when the source only shows that the harness author disliked certain characters, when the input is an opaque string/key accepted by contract, or when there is no visible selector grammar or structural invariant.
Classify such a crash as an API bug when all of the following are better supported than the driver-misuse hypothesis:
1. the abort/assert/trap is control-dependent on the result or state produced by a target API call;
2. the checked predicate expresses a plausible API contract, parser invariant, data-structure invariant, bounds invariant, ownership invariant, or semantic consistency property;
3. the evidence does not show that the harness itself created an invalid call sequence, invalid lifetime, invalid buffer, incompatible configuration, or arbitrary condition unrelated to target API semantics.
Classify it as a driver bug or insufficient evidence only when the abort/assert/trap check is clearly unrelated to any target API result/state, or when the source explicitly shows that the target API behavior is permitted by the visible API contract and the harness expectation is unsupported.
For oracle crashes, root_cause_location may name the target API function and semantic invariant even when the final crashing line is the driver abort/assert/trap. Do not use the driver abort line alone as decisive root-cause evidence. For a supported post-call oracle, decision_basis should be target_evidence. In that case, prefer a target-side semantic label rather than a driver-oriented label.
Illustrative positive pattern:
driver parses or constructs input -> driver calls a target API -> target API returns a result or state -> driver aborts only if that result/state violates an expected contract or invariant.
In that pattern, the final abort/assert/trap is the reporting mechanism, not the root cause. Prefer a target-side semantic bug class such as semantic-contract-violation, lookup-invariant-violation, or unexpected-acceptance rather than inventing a driver-oriented label.
When a post-call oracle is present, a driver_dominant_stack observation only describes where the oracle reported the failure. It must not override target API evidence created by the return value, target-owned state, lookup result, or semantic acceptance that made the oracle fire.

Registered callback oracle rule:
If abort/assert/trap occurs inside a callback, handler, hook, visitor, pull/push function, or event function that the driver registered with a target parser/decoder/resolver, do not treat it as a normal driver-local assertion by default.  The callback arguments are target-produced output state, and the call stack often contains target frames below the callback.
Classify as is_api_bug=true when all of the following are better supported:
1. the callback was registered through a target API and invoked during a target parse/decode/process operation;
2. the abort predicate checks a callback argument supplied by the target, such as a parsed name/token/path/namespace/event/output buffer;
3. the predicate is tied to a parser/decoder/output invariant, configured delimiter/separator semantics, token structure, bounds rule, or API-level output contract.
For example, if a target parser is configured with a namespace/path/token separator and then invokes a callback with a name containing an impossible number or placement of separators, a callback abort that detects this malformed target-produced name is target semantic evidence, not an arbitrary harness filter.
Classify as driver misuse only when the callback predicate is plainly unrelated to target-produced semantics, such as random value thresholds, coverage sentinels, logging policies, or application-specific preferences with no parser/decoder/API invariant.

Timeout/hang rule:
For TimeOut, hang, infinite-loop, or resource-exhaustion reports, do not set is_api_bug=true merely because target-library frames appear in the stack.
Require evidence that the target component enters abnormal non-progress, unbounded recursion/allocation, algorithmic blow-up, or contract-violating behavior for a valid API usage.
If the timeout can be explained by normal blocking behavior, environment-dependent I/O, unsupported configuration, or an unconstrained fuzz-driver workload, prefer false or insufficient_evidence.
"""


_DIFFERENTIAL_V2_DECISION_OUTPUT_CONTRACT = """
Return exactly one valid JSON object and no markdown or surrounding text. Use this schema:
{
  "caller_precondition_verdict": "valid|violated|unclear",
  "precondition_violations": ["concrete caller-side violation, or empty list"],
  "tolerance_contract_evidence": "visible target API contract relevant to the exact behavior under review, or empty string",
  "is_api_bug": true,
  "crash_category": "string",
  "root_cause_type": "string",
  "root_cause_location": "file:line, unknown when unavailable",
  "root_cause_trigger": "string",
  "severity": "critical|high|medium|low|unknown",
  "data_flow": ["ordered key step"],
  "fix_suggestion": "string",
  "confidence": 0.0,
  "decision_basis": "target_evidence|driver_evidence|insufficient_evidence",
  "evidence_summary": "short causal explanation that identifies the fault origin and the decisive contract evidence"
}

The JSON fields are outputs of your own analysis, not evidence to be copied from
the prompt. Fill them only after comparing both attribution hypotheses.
"""


_DIFFERENTIAL_V2_ANALYSIS_INSTRUCTIONS = """Analyze the supplied evidence to determine whether the fault originates
in the primary target component or in the generated fuzz driver.

The sanitizer's crash-frame location is a symptom, not sufficient attribution
evidence. Do not use prior labels, expected label distributions, benchmark
outcomes, or prompt-variant names as evidence.

First reconstruct the causal path:
- Identify the target-facing calls and their actual arguments.
- Determine where each buffer, object, handle, length, and state originated.
- Trace ownership, lifetime, initialization, and required state transitions.
- Determine which properties are attacker-controlled data and which are
  caller-side call-contract properties.

Separate malformed data from malformed calls:
- Malformed bytes delivered through a documented data buffer and explicit
  length are legitimate fuzz input. The target may still be responsible for
  crashing on such input.
- Invalid pointer provenance, a pointer/length relation that exceeds the
  underlying allocation, an invalid object representation, an incompatible
  lifecycle or ownership transition, or an impossible required state is a
  caller-side contract problem.
- Missing required storage capacity, termination, alignment, padding, or
  sentinel state is a caller-side contract problem when the target source
  requires that property.
- Starting from an invalid protocol state is a caller-side problem, whereas
  malformed payload received after a valid state transition can expose a
  target defect.
- Ignoring a required transition or status check before later processing is a
  caller-side problem.

Evaluate component scope:
- A primary-target defect belongs to the component under evaluation or to a
  dependency exposed through its documented public behavior.
- A crash from the driver directly invoking an auxiliary or separately scoped
  dependency is not sufficient evidence for a primary-target defect unless the
  evidence establishes that dependency as part of the evaluated target surface.

Perform two counterfactual comparisons:

Driver-repair hypothesis:
Keep the same attacker-controlled data, but use a documented valid call
structure, state sequence, pointer provenance, allocation extent, required
storage capacity, and lifecycle. Would the same invalid memory access or broken
invariant still occur?

Target-defect hypothesis:
Assume every visible call and state contract is satisfied. Is there a specific
target-side rule, arithmetic path, lifetime behavior, or validation failure
that still produces the crash?

Decision criteria:
- Return true only when the target-defect hypothesis is more specifically
  supported and the driver-repair hypothesis does not explain the crash.
- Return false when a caller-side contract or state-sequence problem is the
  more specific cause.
- Do not return true merely because the crash frame is in target code, a target
  function appears in the stack, or an additional defensive check could have
  prevented the crash.
- Do not return false merely because the payload bytes are attacker-controlled
  or malformed.
- Prefer causal specificity over generic robustness claims.
- If the evidence conflicts or is incomplete, make the best-supported binary
  decision and explain the unresolved evidence and confidence in the JSON.

When the supplied evidence contains a public vulnerability reference, require
agreement in the crashing path, affected code, and affected-version evidence.
A match by symbol name alone is insufficient.

Before finalizing the JSON, perform one internal rebuttal:
- State the strongest evidence against the current decision.
- Check whether malformed payload data was mistaken for caller-contract misuse.
- Check whether caller-contract misuse was mistaken for a missing target check.
- Check whether the crashing operation was reached through a valid state
  sequence and the evaluated component surface.
- Change the decision if the supplied evidence supports the opposite
  attribution more strongly.

Explain the fault origin, the decisive caller or target contract, and why the
selected hypothesis is more specific. Do not manufacture source facts,
contracts, runtime state, or public references.
"""


_DIFFERENTIAL_V3_DECISION_OUTPUT_CONTRACT = """
Return exactly one valid JSON object and no markdown or surrounding text. Use this schema:
{
  "caller_precondition_verdict": "valid|violated|unclear",
  "driver_misuse_evidence_strength": "hard|soft|none",
  "driver_misuse_location": "exact driver file:line and violated contract, or empty string",
  "target_surface_evidence": "the public target input/object/state that reaches the failing operation, or empty string",
  "precondition_violations": ["concrete caller-side violation, or empty list"],
  "tolerance_contract_evidence": "visible target API contract relevant to the exact behavior under review, or empty string",
  "is_api_bug": true,
  "crash_category": "string",
  "root_cause_type": "string",
  "root_cause_location": "file:line, unknown when unavailable",
  "root_cause_trigger": "string",
  "severity": "critical|high|medium|low|unknown",
  "data_flow": ["ordered key step"],
  "fix_suggestion": "string",
  "confidence": 0.0,
  "decision_basis": "target_evidence|driver_evidence|insufficient_evidence",
  "evidence_summary": "short causal explanation that identifies the fault origin and the decisive evidence"
}

The fields are outputs of your own analysis. Set driver_misuse_evidence_strength
to "hard" only when the exact driver code and a visible or source-supported
contract establish a decisive caller violation. A plausible repair, absent
documentation, or a generic request for more defensive validation is "soft".
"""


_DIFFERENTIAL_V3_ANALYSIS_INSTRUCTIONS = """Analyze the supplied evidence to determine whether the crash should be
attributed to the primary target component or is decisively caused by the
generated fuzz driver.

This is not a test of whether the driver is an ideal harness. Incompetent or
contract-violating generated drivers are expected. The question is which
hypothesis better explains the observed target failure.

Do not use prior labels, project identities, expected label distributions,
benchmark outcomes, public-reference names, or prompt-version names as labels.
Use them only when the evidence independently establishes the same crash path
and affected behavior.

Step 1: reconstruct the causal path.
- Identify the target-facing call that admitted the input or created the failing
  state.
- Trace the origin, ownership, lifetime, allocation extent, and validation of
  every relevant pointer, object, length, and state value.
- Separate attacker-controlled payload bytes from caller-controlled call
  structure and from target-created state.

Step 2: classify suspected driver misuse. Do not treat every suspicion as a
proven violation.

Hard misuse requires exact evidence from the driver and, where applicable, a
visible header, API contract, source implementation, or reproduced state:
- A pointer is NULL, freed, out of allocation, or incompatible with the object
  type expected by the called API.
- A pointer/length pair exceeds the backing allocation for an API that is
  plainly a raw memory copy/read operation and has no protocol-level way to
  validate the claimed extent.
- An object was fabricated with the wrong concrete layout or passed to the
  wrong allocator/deallocator family.
- A target-created object or handle was closed, freed, or invalidated before a
  later use.
- The driver demonstrably ignored a status or required state transition whose
  documented failure leaves the later call invalid. The evidence must show the
  failed status or invalid state, not merely infer it from a missing check.
- Visible API documentation explicitly forbids the exact argument or state
  transition used by the driver.

The following are generally soft concerns, not hard misuse:
- malformed or adversarial payload bytes delivered in a declared data buffer;
- extreme but type-correct scalar lengths, counts, indices, or metadata values
  accepted by a public API;
- mutation of fields on a live object created by the matching target
  constructor or open/new/parse API when that public API later accepts the
  object;
- a callback receiving a name, path, token, or output state produced by the
  target parser;
- a public file, URI, source, or resource string that the target API is
  responsible for parsing, opening, or rejecting;
- deeply nested, highly repetitive, or otherwise structurally hostile input
  delivered through a documented byte-buffer API;
- the mere absence of an additional defensive check, bounds check, recursion
  limit, or error check inside the target;
- incomplete source visibility or an unavailable reproduction by itself.

Step 3: apply a symmetric decision rule.
- If hard misuse is established and no visible contract requires the target to
  tolerate that exact behavior, return false.
- If no hard misuse is established, determine whether a target-side memory
  operation, assertion, resource non-progress, or invariant still fails on the
  admitted public input or target-created state. Return true when that
  target-side failure is more specific than a soft misuse hypothesis.
- Do not return false merely because a stricter driver could have avoided the
  crash, the final sanitizer frame is in driver-adjacent code, or the input is
  malformed.
- Do not return true merely because the crash frame is in target code. For true
  attribution, name the target-side operation or invariant that fails and the
  public path through which the relevant input or state reached it.

Step 4: perform the counterfactual correctly.
- Driver-repair hypothesis: repair only a concrete hard misuse identified in
  the actual driver while preserving the same attacker-controlled data values.
  Do not invent a different API, a different object, or a more defensive target
  implementation and call that a driver repair.
- Target-defect hypothesis: keep the same public input values and valid call
  structure. Identify the target rule, arithmetic, lifetime, validation, or
  resource behavior that still fails.
- If the only difference between hypotheses is the target gaining a generic
  defensive check, the comparison is insufficient for false attribution when
  the crash is a concrete memory-safety or non-progress failure reached through
  the public boundary.

Before finalizing, audit both mistakes:
- Did you label an attacker-controlled data value as caller misuse?
- Did you infer a precondition that is not present in visible documentation or
  source?
- Did you ignore an explicit positive boundary candidate in the evidence?
- Did you call an unverified initialization failure or object defect "hard"
  without showing the failed status or invalid layout?
- Conversely, did you excuse a wrong deallocator, fabricated object, invalid
  pointer, or invalid lifetime merely because the final crash remained in target
  code?

Prefer the most concrete causal explanation. Do not manufacture source facts,
contracts, runtime state, or public references.
"""


_DIFFERENTIAL_V4_ANALYSIS_INSTRUCTIONS = _DIFFERENTIAL_V3_ANALYSIS_INSTRUCTIONS + """

Final arbitration rules for boundary cases:

- A callback registered through a public target API and invoked by the target
  parser, decoder, resolver, or event loop is executing on target-produced
  output. Do not classify the callback as hard misuse merely because it
  dereferences or bounds-checks a target-produced name, path, token, buffer, or
  state. The callback is useful evidence that the target produced an invalid
  value, unless the callback itself overwrites or frees target-owned memory.
- If the evidence identifies a live object created by the matching target
  constructor/open/new/parse API and the driver changes fields that are visible
  through a public definition, classify that action as at most soft evidence.
  A crash in a later public target operation that computes addresses, sizes, or
  bounds from those fields supports target attribution.
- A caller-owned public structure that is actually allocated and passed with
  its declared size is not "uninitialized" merely because its field values are
  derived from adversarial bytes. Treat it as boundary data. It is hard misuse
  only when the storage itself is absent, too small for the declared type, or
  contains a pointer that the driver never made usable.
- Do not infer that a special scalar value, sentinel, negative index, or
  unusual stream state is forbidden unless the visible API/header/source
  establishes that restriction or the evidence shows the corresponding call
  returned an explicit failure.
- When no hard misuse is established and the evidence identifies a
  target-side memory operation, assertion, non-progress path, or invariant
  failure reached through target-created state, return true.
- Final fields must be internally consistent:
  driver_misuse_evidence_strength="hard" supports false only when that misuse
  is the decisive cause;
  decision_basis="target_evidence" together with soft/no hard misuse supports
  true;
  decision_basis="driver_evidence" requires the concrete driver-side cause.
- A generic robustness statement or the statement that a different driver
  could avoid the input is not enough to set hard misuse.
"""


_DIFFERENTIAL_V4_DECISION_OUTPUT_CONTRACT = _DIFFERENTIAL_V3_DECISION_OUTPUT_CONTRACT + """
Before returning, verify that is_api_bug agrees with decision_basis.
If decision_basis is "target_evidence", use is_api_bug=true unless a concrete
hard misuse is also identified and is the direct cause. If the final answer is
false, driver_misuse_evidence_strength must not be "none".
"""


_DIRECT_V1_OUTPUT_CONTRACT = """
Return exactly one valid JSON object and no markdown or surrounding text. Use this schema:
{
  "caller_precondition_verdict": "valid|violated|unclear",
  "precondition_violations": ["concrete caller-side violation, or empty list"],
  "tolerance_contract_evidence": "visible target API contract, or empty string",
  "is_api_bug": true,
  "crash_category": "string",
  "root_cause_type": "string",
  "root_cause_location": "file:line, unknown when unavailable",
  "root_cause_trigger": "string",
  "severity": "critical|high|medium|low|unknown",
  "data_flow": ["ordered key step"],
  "fix_suggestion": "string",
  "confidence": 0.0,
  "decision_basis": "target_evidence|driver_evidence|insufficient_evidence",
  "evidence_summary": "short explanation naming the decisive evidence"
}

State the final attribution supported by the supplied evidence. Report concrete
caller-side violations only when they are visible in the evidence, and record
missing evidence in decision_basis or evidence_summary. Do not invent source
facts, contracts, or runtime state. Set driver_misuse_evidence_strength to
"hard" only when a concrete driver-side misuse is the decisive cause; use
"soft" for avoidability or defensive-check concerns that do not establish
caller-contract misuse.
"""


_DIFFERENTIAL_ANALYSIS_INSTRUCTIONS = """Based on ALL of the above information, provide a comprehensive analysis.

The pre-filter labeled this crash as "{triage_label}" with confidence {triage_confidence}.
Explicitly compare the target-component-defect hypothesis with the driver-misuse hypothesis.
Only attribute the crash to the target component when that hypothesis is better supported by the supplied evidence.
Use this short checklist before the final boolean:
- Positive callback oracle: callback registered with target + callback argument supplied by target + predicate checks parser/decoder/output invariant => target evidence.
- Positive exposed-object boundary state: target-created live mutable object + exposed metadata mutation + public target API crashes on unchecked size/position/capacity arithmetic/memory operation => target evidence; do not call it fabricated misuse solely because target source is unavailable or metadata is extreme.
- Positive extreme public length: live handle/pointer + explicit public length/count boundary value + target fails to reject impossible/overflowing value before read/copy => target evidence.
- Positive public source/URI boundary: existing NUL-terminated file/path/URI source + public parser/enumerator/open API + target dereferences NULL resource/parser/directory state instead of returning an error => target evidence.
- Positive format metadata length: live archive/container handle + public entry/header API + explicit extra-field/comment/header/name/filename metadata pointer/length + target source/signature shows metadata/header construction or fixed-width metadata fields + target fails to reject impossible/truncating metadata before header construction/arithmetic/read/traversal => target evidence; do not treat this as ordinary raw pointer+length misuse unless the API is a simple raw read/copy/compress function.
- Archive metadata consistency: if SECTION 5C marks an archive/container metadata boundary, "length exceeds actual fuzz buffer" is not enough for false; false requires showing simple raw copy/read/compress API, invalid handle/pointer, or an explicit visible contract making that metadata length a caller precondition.
- Mandatory false gates: wrong deallocator/internal layout, fabricated object, ownership-transfer cleanup misuse, non-NUL C string/key to a no-length API, sanitizer-only intentional word-at-a-time hash/string overread, ignored/unchecked init/config/status followed by decode/process, arbitrary reset/config/stream reuse, unconfigured resolver/device/environment resource, or raw pointer+length that overstates readable memory => driver evidence unless a visible API contract explicitly says the target must tolerate that exact misuse.
- Consistency rule: if your own data_flow/evidence/fix says the driver should change deallocator, NUL-terminate, check init/config success, avoid fabricated objects, avoid reset/reuse/config misuse, supply environment resources, or pass a truthful buffer length, the final is_api_bug must be false unless you cite a concrete visible target contract requiring tolerance.
- Do not use "the library should handle malformed input gracefully", "the target stack crashed", or "the API documentation is unclear" as the reason for true; require a target invariant failure after driver preconditions are satisfied.
If the final crash frame is abort/assert/trap in the fuzz driver, explicitly analyze whether this is:
A) driver misuse or an arbitrary harness failure, or
B) a driver-side oracle reporting a target API invariant violation.
Do not stop at the final stack frame. Trace the condition that reaches the abort/assert/trap back to the immediately preceding target API call and the value or state returned by that API.
If that condition is gated by a target API return value or target-owned state, treat it as a candidate oracle and decide whether the checked predicate is tied to a visible API contract/invariant or only to a harness-local expectation.
If the driver aborts after a successful target parse/lookup/transform and the abort predicate depends on the returned or derived state, analyze both possibilities: target semantic violation versus arbitrary harness constraint.  Attribute it to the target only when the semantic tie is better supported.
For lookup/selector/path/key/index APIs, a successful non-null lookup followed by a driver abort on malformed selector syntax is target unexpected-acceptance only when the selector is a structured target-interpreted grammar/path/key/index and the API does not visibly permit partial, prefix, fallback, opaque-key, or best-effort behavior.
Before returning true, check whether the same evidence is better explained by driver misuse, invalid lifetime/object construction, arbitrary harness filtering, timeout/resource policy, or opaque-string behavior.  If concrete driver misuse better explains how the invalid state reaches the sanitizer/oracle failure, classify as false even when the sanitizer frame is inside target code.
For sanitizer crashes involving free/delete/destructor/use-after-free/bad-free/double-free or cleanup traversal, explicitly audit ownership: matching allocator/deallocator family, ownership transfer after add/append/attach/insert/set, use after cleanup/delete/free/release, and fabricated or partially initialized objects.  If this ownership audit points to driver misuse, return false even when the top sanitizer frame is inside the target library.

Please determine:
1. **Is this an API bug?** (True = target-component attribution is supported; False = fuzz driver quality issue or insufficient evidence)
2. **Root cause type**: e.g., null-pointer-dereference, heap-buffer-overflow, use-after-free, uninitialized-memory, integer-overflow, etc.
3. **Root cause location**: The specific file:line in the TARGET LIBRARY where the root cause exists
4. **Trigger condition**: What input/state triggers this vulnerability
5. **Data flow**: How does data flow from the fuzz driver input to the crash point? List key steps.
6. **Severity**: critical / high / medium / low
7. **Fix suggestion**: How should the code be fixed?
8. **Crash category**: One of: {init_crash}. If none fits, suggest a new category.

Compare the target-component-defect and driver-misuse hypotheses using concrete evidence, then follow the final JSON output contract."""

_DIRECT_V1_ANALYSIS_INSTRUCTIONS = """Based on the supplied evidence, determine the final attribution for this crash.

The pre-filter labeled this crash as "{triage_label}" with confidence
{triage_confidence}. Treat that label as routing information, not ground truth
or direct evidence.

Reconstruct the fault path at the level supported by the supplied evidence.
Identify which values and objects came from attacker-controlled input, which
were created by the target, and which call structure or lifetime was controlled
by the driver. Then state the final attribution directly.

Use driver attribution only when the evidence identifies a concrete
driver-side violation that is decisive for this crash, such as an invalid
pointer, wrong allocation/deallocation family, invalid object layout, invalid
lifetime or state transition, or a required failure/status transition that was
demonstrably ignored. Malformed payload bytes, an extreme value accepted by a
public parameter, a target-produced callback value, or the fact that a
different driver could avoid the crash do not by themselves establish hard
driver misuse.

Use target attribution when the evidence identifies a target-side memory
operation, assertion, non-progress path, or invariant failure reached through
an admitted public input or target-created state. Do not require the target to
have an explicit promise to tolerate arbitrary malformed payloads; the decisive
question is whether the concrete driver defect better explains how the invalid
state was produced.

Keep the final fields internally consistent. If decision_basis is
"target_evidence", is_api_bug should be true unless a concrete hard driver
misuse is also identified as the direct cause. If is_api_bug is false,
driver_misuse_evidence_strength must not be "none". Do not manufacture source
facts, contracts, runtime state, or public references. Follow the final JSON
output contract."""


_DIFFERENTIAL_V5_ANALYSIS_INSTRUCTIONS = _DIRECT_V1_ANALYSIS_INSTRUCTIONS + """

Before making the final decision, compare the target-defect and driver-misuse
explanations once.

Treat driver misuse as decisive only when the evidence establishes concrete
hard misuse: an invalid or freed pointer, an impossible object layout or
allocation family, a wrong deallocator/constructor family, a definitively
invalid handle, or an ignored failure whose resulting invalid state is directly
shown. Do not infer hard misuse merely from malformed payload data, an extreme
value accepted by a public parameter, a live target-created object with exposed
fields, a target-produced callback argument, a public path/source string, or
the absence of an additional defensive check.

If hard misuse is the decisive cause, return false. Otherwise evaluate whether
the target-side memory operation, assertion, resource behavior, or invariant
fails on the admitted input or target-created state. Return true when that
target-side failure is better supported, even when the final abort or check is
located in driver-side code.

Do not require the model to invent a different valid call. A driver repair must
correct a violation visible in the actual driver while preserving the same
attacker-controlled data values. Do not manufacture source facts, contracts,
runtime state, or public references.
"""


_DIFFERENTIAL_V5_DECISION_OUTPUT_CONTRACT = _DIFFERENTIAL_V4_DECISION_OUTPUT_CONTRACT

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


_ARCHIVE_METADATA_REPAIR_PROMPT = """Your previous JSON violates a required consistency rule.

Relevant evidence from the original prompt:
{relevant_context}

Required consistency rule:
If SECTION 5C lists "Archive/container metadata length boundary candidate", and target source/signature shows an archive/container entry/header metadata parameter such as extra-field/comment/header/name/central/local header metadata, then "the metadata length exceeds the actual fuzz buffer size" is NOT sufficient to classify the crash as driver_evidence.

You may keep is_api_bug=false only if you can explicitly show one of these disqualifiers from the evidence:
1. the crashing API is a simple raw copy/read/compress API rather than an archive/container entry/header API;
2. the archive/container handle or metadata pointer is invalid/null in a way the API forbids;
3. a visible API/header contract explicitly makes this exact metadata length relationship a caller precondition.

Previous JSON:
{previous_json}

Return exactly one corrected valid JSON object using the original schema. No markdown. If none of the three disqualifiers is supported, set caller_precondition_verdict to "valid" or "unclear", set decision_basis to "target_evidence", and classify the crash as the target failing to reject impossible archive/container entry metadata before header construction or metadata traversal."""


_NEGATIVE_BOUNDARY_REPAIR_PROMPT = """Your previous JSON appears internally inconsistent with a hard driver-misuse boundary.

This is a consistency audit, not a project-specific override.

Reason this audit was triggered:
{violation}

Relevant evidence from the original prompt:
{relevant_context}

Required rule:
If concrete driver-originating misuse better explains how the invalid state reaches the crash, classify is_api_bug=false even when the sanitizer frame is inside target code.  Generic statements such as "the library should validate", "should handle malformed input gracefully", or "the target stack crashed" are not visible API contracts requiring the target to tolerate invalid caller behavior.

Keep is_api_bug=true only if the relevant evidence shows a valid public boundary test after caller preconditions are satisfied, and cite the concrete visible API/header/source evidence that makes the target-component hypothesis stronger than the driver-misuse hypothesis.  Otherwise set caller_precondition_verdict="violated", decision_basis="driver_evidence", and is_api_bug=false.

Previous JSON:
{previous_json}

Return exactly one corrected valid JSON object using the original schema. No markdown."""


def _strip_code_fence(text: str) -> str:
    """Remove a single optional Markdown code fence around an LLM response."""
    stripped = (text or "").strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\\s*```$", "", stripped)
    return stripped.strip()


def _parse_enhanced_json_response(text: str) -> EnhancedCrashAnalysis:
    """Validate the first JSON object in the primary model response locally.

    The old path asked the LLM to interpret its own natural-language response in
    a second request. That second stochastic request can invert the decision.
    Keep parsing deterministic whenever the primary model follows the JSON
    contract; callers may explicitly use the legacy extractor only as a
    malformed-response fallback.
    """
    raw = _strip_code_fence(text)
    candidates = [raw]
    object_start = raw.find("{")
    if object_start > 0:
        candidates.append(raw[object_start:])

    last_error = None
    for candidate in candidates:
        try:
            decoder = json.JSONDecoder()
            payload, _ = decoder.raw_decode(candidate.lstrip())
            if not isinstance(payload, dict):
                raise ValueError("response JSON must be an object")
            if hasattr(EnhancedCrashAnalysis, "model_validate"):
                return EnhancedCrashAnalysis.model_validate(payload)
            return EnhancedCrashAnalysis.parse_obj(payload)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            last_error = exc

    raise ValueError(f"primary response is not valid EnhancedCrashAnalysis JSON: {last_error}")


def _enhanced_result_text(result: EnhancedCrashAnalysis) -> str:
    parts = [
        str(getattr(result, "caller_precondition_verdict", "")),
        " ".join(getattr(result, "precondition_violations", []) or []),
        str(getattr(result, "tolerance_contract_evidence", "")),
        str(getattr(result, "decision_basis", "")),
        str(getattr(result, "evidence_summary", "")),
        str(getattr(result, "fix_suggestion", "")),
        " ".join(getattr(result, "data_flow", []) or []),
        str(getattr(result, "root_cause_trigger", "")),
    ]
    return "\n".join(parts)


def _extract_prompt_section(prompt: str, start_marker: str, end_marker: str) -> str:
    """Return one prompt section, so global instruction text is not mistaken for evidence."""
    if not prompt:
        return ""
    start = prompt.find(start_marker)
    if start < 0:
        return ""
    end = prompt.find(end_marker, start + len(start_marker))
    if end < 0:
        return prompt[start:]
    return prompt[start:end]


def _actual_precondition_risk_context(prompt: str) -> str:
    return _extract_prompt_section(prompt, "SECTION 5C: CALLER PRECONDITION RISK CONTEXT", "SECTION 5D:")


def _has_actual_archive_metadata_candidate(prompt: str) -> bool:
    return "Archive/container metadata length boundary candidate" in _actual_precondition_risk_context(prompt)


def _archive_metadata_consistency_violation(result: EnhancedCrashAnalysis, prompt: str) -> str:
    if not _has_actual_archive_metadata_candidate(prompt):
        return ""
    if not re.search(
        r"(?:extra[-_ ]?field|extrafield|comment|header|filename|entry metadata|central_header|local header|size_extrafield)",
        prompt,
        re.IGNORECASE,
    ):
        return ""

    verdict = (getattr(result, "caller_precondition_verdict", "") or "").lower()
    is_false = getattr(result, "is_api_bug", None) is False
    if verdict != "violated" and not is_false:
        return ""

    text = _enhanced_result_text(result)
    buffer_mismatch = re.search(
        r"(?:actual|backing|available|fuzz).{0,40}(?:buffer|data|size)|"
        r"(?:buffer|data|size).{0,40}(?:actual|backing|available|fuzz)|"
        r"pass(?:es|ing)?\\s+UINT_MAX|should\\s+(?:use|pass).*actual|exceeds\\s+(?:the\\s+)?(?:actual|backing|available)",
        text,
        re.IGNORECASE,
    )
    if not buffer_mismatch:
        return ""

    has_disqualifier = re.search(
        r"simple\\s+raw\\s+(?:copy|read|compress)|raw\\s+(?:copy|read|compress)\\s+API|"
        r"invalid\\s+(?:archive\\s+)?handle|invalid\\s+(?:metadata\\s+)?pointer|null\\s+(?:metadata\\s+)?pointer|"
        r"explicit\\s+(?:visible\\s+)?(?:API|header)\\s+contract|caller\\s+precondition\\s+explicitly",
        text,
        re.IGNORECASE,
    )
    if has_disqualifier:
        return ""

    return (
        "archive metadata candidate was classified false using only actual/backing fuzz buffer size mismatch, "
        "without proving a simple raw copy/read/compress API, invalid handle/pointer, or explicit visible caller precondition"
    )


def _prompt_snippets_for_needles(prompt: str, needles: List[str], window: int = 900, max_chars: int = 5000) -> str:
    snippets: List[str] = []
    seen = set()
    for needle in needles:
        idx = prompt.find(needle)
        if idx < 0:
            continue
        start = max(0, idx - window)
        end = min(len(prompt), idx + window)
        key = (start, end)
        if key in seen:
            continue
        seen.add(key)
        snippets.append(prompt[start:end])
    joined = "\n\n---\n\n".join(snippets)
    return _truncate(joined, max_chars, "archive_metadata_repair_context")


def _negative_boundary_consistency_violation(result: EnhancedCrashAnalysis, prompt: str) -> str:
    """Detect true decisions that contradict explicit driver-misuse evidence.

    This does not change the decision locally.  It only decides whether to ask
    the LLM for a focused consistency repair under the same JSON schema.
    """
    if getattr(result, "is_api_bug", None) is not True:
        return ""

    precondition_context = _actual_precondition_risk_context(prompt)
    text = _enhanced_result_text(result)
    lower = text.lower()

    # Do not use this negative audit to fight the deliberately narrow positive
    # patterns that were added to protect recall.
    if _has_actual_archive_metadata_candidate(prompt):
        return ""
    if "Target-created exposed object boundary-state candidate" in precondition_context and re.search(
        r"\b(?:exposed|boundary-state|target-created|live object)\b", text, re.IGNORECASE
    ):
        return ""
    if "POST-CALL ORACLE DETECTED" in prompt and re.search(
        r"\b(?:oracle|unexpected[- ]acceptance|target api returned|callback argument|semantic invariant)\b",
        text,
        re.IGNORECASE,
    ):
        return ""

    tolerance = (getattr(result, "tolerance_contract_evidence", "") or "").strip().lower()
    generic_tolerance = bool(
        tolerance
        and re.search(
            r"\b(?:should|gracefully|robust|validate|handle malformed|not crash|api accepts|library failed)\b",
            tolerance,
        )
        and not re.search(r"\b(?:header|documentation|manual|contract|requires|guarantees|explicitly|must)\b", tolerance)
    )

    if re.search(r"actually reads beyond the end of the string", prompt, re.IGNORECASE) and re.search(
        r"\b(?:valgrind|masked|masking trick|word-at-a-time|hashlittle|hash|string)\b", prompt, re.IGNORECASE
    ):
        return "target source describes an intentional word-at-a-time string/key overread that masks the tail; previous JSON classified the sanitizer read as a target bug without separate semantic/write evidence"

    if re.search(r"(?:Raw fuzz C-string risk|No-length string API risk|Borrowed substring array risk)", precondition_context):
        if re.search(r"\b(?:unterminated|strlen|string traversal|string length|no explicit length|without length|fuzz-derived char pointer)\b", lower):
            return "previous JSON classified true even though SECTION 5C shows a no-length C-string/string-array risk and the reasoning relies on strlen/string traversal over fuzz-derived or borrowed string data"
        if generic_tolerance:
            return "previous JSON used generic string-validation robustness language as tolerance evidence for a no-length C-string/string-array risk"

    strong_ownership_risk = re.search(r"(?:Ownership-transfer failure-path risk|Manual target object fabrication risk)", precondition_context)
    generic_ownership_risk = "Ownership/deallocator risk" in precondition_context
    ownership_ack = re.search(
        r"\b(?:driver|fuzz driver|harness|caller).{0,120}\b(?:incorrect|manual|mock|fabricat|free|decref|delete|destroy|cleanup|ownership|already freed|double[- ]free|same memory|also attempts|attempts to free)\b|"
        r"\b(?:free|decref|delete|destroy|cleanup|ownership|double[- ]free|same memory|already freed).{0,120}\b(?:driver|fuzz driver|harness|caller|mock|fabricat)\b",
        lower,
    )
    ownership_positive_language = re.search(
        r"\b(?:properly|correctly|validly|follows the api|correct api|matching target api|no evidence of driver)\b",
        lower,
    )
    if strong_ownership_risk or generic_ownership_risk:
        if ownership_ack and (strong_ownership_risk or not ownership_positive_language):
            return "previous JSON classified true while its own reasoning or SECTION 5C points to driver-side ownership/deallocator/fabricated-object misuse"
        if generic_tolerance and strong_ownership_risk:
            return "previous JSON used generic robustness language as tolerance evidence despite ownership/deallocator/fabricated-object risk"

    if re.search(r"(?:Stateful API protocol risk|Stateful stream/reset/decode risk|Unchecked state/status result risk|Direct object/stream metadata mutation risk|Post-parse error-state use risk)", precondition_context):
        if re.search(
            r"\b(?:driver|fuzz driver|harness).{0,120}\b(?:ignored|unchecked|arbitrary|reset|seek|configuration|configured|stream state|decoder state|parser state|parse failure|failed parse|post-parse|no root|without re-establishing|directly mutates)\b|"
            r"\b(?:ignored|unchecked|arbitrary|reset|seek|configuration|stream state|decoder state|parser state|parse failure|failed parse|post-parse|no root|without re-establishing|directly mutates).{0,120}\b(?:driver|fuzz driver|harness)\b",
            lower,
        ):
            return "previous JSON classified true while SECTION 5C indicates an unchecked state/status, reset/configuration, direct stream-field mutation, or post-parse error-state risk on the crash path"
        if generic_tolerance and re.search(r"(?:Unchecked state/status result risk|Direct object/stream metadata mutation risk|Post-parse error-state use risk)", precondition_context):
            return "previous JSON used generic robustness language as tolerance evidence despite stateful protocol/reset/configuration risk"

    return ""


def _repair_negative_boundary_consistency_with_llm(
    llm: Any,
    *,
    prompt: str,
    previous_response: str,
    previous_result: EnhancedCrashAnalysis,
) -> tuple[EnhancedCrashAnalysis, str, str]:
    violation = _negative_boundary_consistency_violation(previous_result, prompt)
    if not violation:
        return previous_result, "", ""

    relevant_context = _prompt_snippets_for_needles(
        prompt,
        [
            "SECTION 5C: CALLER PRECONDITION RISK CONTEXT",
            "SECTION 5D: DECISIVE EVIDENCE AUDIT",
            "SECTION 5: FUZZ DRIVER SOURCE CODE",
            "TARGET CRASH SOURCE CONTEXT",
            "Final precondition gate",
            "Hard negative boundary rule",
            "Decisive driver-misuse boundary",
            "String/key/hash traversal boundary",
            "Ownership/deallocator boundary rule",
            "Stateful stream/reset/decode protocol boundary",
        ],
        max_chars=7000,
    )
    repair_prompt = _NEGATIVE_BOUNDARY_REPAIR_PROMPT.format(
        violation=violation,
        relevant_context=relevant_context,
        previous_json=_strip_code_fence(previous_response),
    )
    repair_response = llm.complete(repair_prompt).text
    repaired_result = _parse_enhanced_json_response(repair_response)
    return repaired_result, repair_response, violation


def _repair_archive_metadata_consistency_with_llm(
    llm: Any,
    *,
    prompt: str,
    previous_response: str,
    previous_result: EnhancedCrashAnalysis,
) -> tuple[EnhancedCrashAnalysis, str, str]:
    violation = _archive_metadata_consistency_violation(previous_result, prompt)
    if not violation:
        return previous_result, "", ""

    relevant_context = _prompt_snippets_for_needles(
        prompt,
        [
            "Archive/container metadata length boundary candidate",
            "TARGET CRASH SOURCE CONTEXT",
            "Function signature / parameter context",
            "Final consistency check for archive/container metadata boundary",
            "Positive archive/container metadata boundary",
        ],
    )
    repair_prompt = _ARCHIVE_METADATA_REPAIR_PROMPT.format(
        relevant_context=relevant_context,
        previous_json=_strip_code_fence(previous_response),
    )
    repair_response = llm.complete(repair_prompt).text
    repaired_result = _parse_enhanced_json_response(repair_response)
    remaining = _archive_metadata_consistency_violation(repaired_result, prompt)
    if remaining:
        raise ValueError(f"archive metadata consistency repair still violates rule: {remaining}")
    return repaired_result, repair_response, violation


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
    # Supports ablation modes for controlled experiments:
    #   include_triage=True  → populate Section 1 (triage evidence)
    #   include_context=True → populate Sections 3+4 (code + runtime)
    # All modes use the SAME prompt template and JSON output schema
    # to ensure prompt fairness (only evidence content varies).
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
        include_triage: bool = True,
        include_context: Optional[bool] = None,
        include_static_context: Optional[bool] = None,
        include_runtime_context: Optional[bool] = None,
        prompt_variant: str = "differential",
        capture_prompt: bool = False,
    ):
        """Enhanced crash analysis with triage, locator, and debugger context.

        Args:
            crash_info: Raw sanitizer output text
            fuzz_driver_path: Path to the fuzz driver source file
            api_combine: List of API function names used by the driver
            triage_result: Output of triage_crash() — pre-filter verdict
            location_result: Output of locate_crash_site() — code context
            runtime_context: Output of reproduce_with_gdb() — runtime state
            include_triage: If False, Section 1 uses placeholder (ablation V0/V1)
            include_context: Legacy switch for both static and runtime context.
            include_static_context: Controls Section 3 independently of runtime context.
            include_runtime_context: Controls Section 4 independently of static context.
            prompt_variant: ``direct_v1`` for ablation V0-V3 or
                ``differential`` for full CrashSage V4.
            capture_prompt: Keep the final prompt in experiment metadata for
                an external runner to persist. Disabled for the main pipeline
                to avoid enlarging crash-analysis records.

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

        # Build structured crash summary (always available — deterministic parse)
        try:
            parsed = parse_sanitizer_output(crash_info or "")
            structured_summary = format_crash_summary(parsed)
        except Exception as e:
            structured_summary = f"[CRASH] parse_failed: {e}"
            parsed = {}

        # ── Section 1: Triage ────────────────────────────────────────
        _NO_TRIAGE = "[PRE-FILTER] No rule-based pre-filter was applied to this crash."
        if include_triage and triage_result:
            triage_evidence_lines = []
            for ev in (triage_result.get("evidences") or []):
                triage_evidence_lines.append(_format_triage_evidence_for_prompt(ev))
            triage_evidence_str = "\n".join(triage_evidence_lines) if triage_evidence_lines else "  (no specific evidence)"
            triage_label = triage_result.get("label", "unknown")
            triage_confidence = triage_result.get("confidence", 0.0)
        else:
            triage_evidence_str = _NO_TRIAGE
            triage_label = "not_available"
            triage_confidence = 0.0

        if include_context is not None:
            if include_static_context is None:
                include_static_context = include_context
            if include_runtime_context is None:
                include_runtime_context = include_context
        if include_static_context is None:
            include_static_context = True
        if include_runtime_context is None:
            include_runtime_context = True
        if include_runtime_context and not include_static_context:
            raise ValueError("Runtime context requires static context in the controlled ablation")
        if prompt_variant not in {"differential", "direct_v1"}:
            raise ValueError(f"Unknown prompt_variant: {prompt_variant}")

        # ── Sections 3+4: Code context & runtime context ─────────────
        _NO_CONTEXT = "[CONTEXT] Source-level code context is not available for this analysis."
        _NO_RUNTIME = "[RUNTIME] Dynamic reproduction and runtime context are not available for this analysis."
        driver_basename = os.path.basename(fuzz_driver_path) if fuzz_driver_path else None
        if include_static_context:
            if location_result is None:
                location_result = locate_crash_site(parsed, driver_basename=driver_basename)
            call_chain_str = format_call_chain_for_llm(location_result, max_frames=5)
            target_source_context = _extract_target_crash_source_context(
                parsed,
                driver_basename=driver_basename,
            )
            public_header_context = _extract_public_header_exposed_struct_context(
                parsed,
                fuzz_driver,
                driver_basename=driver_basename,
            )
            call_chain_str = f"{call_chain_str}\n\n{target_source_context}\n\n{public_header_context}"
        else:
            call_chain_str = _NO_CONTEXT

        if include_runtime_context:
            if runtime_context and runtime_context.get("reproduced"):
                runtime_str = format_runtime_context_for_llm(runtime_context)
            else:
                runtime_str = "[RUNTIME] Dynamic reproduction not available for this crash."
        else:
            runtime_str = _NO_RUNTIME

        if prompt_variant == "differential":
            analysis_instructions = _DIFFERENTIAL_V4_ANALYSIS_INSTRUCTIONS.format(
                triage_label=triage_label,
                triage_confidence=triage_confidence,
                init_crash=", ".join(self.init_crash),
            )
            output_contract = _DIFFERENTIAL_V4_DECISION_OUTPUT_CONTRACT
        else:
            analysis_instructions = _DIRECT_V1_ANALYSIS_INSTRUCTIONS.format(
                triage_label=triage_label,
                triage_confidence=triage_confidence,
            )
            output_contract = _DIRECT_V1_OUTPUT_CONTRACT
        analysis_instructions += output_contract

        # Truncate long sections to prevent token overflow
        driver_oracle_context = _extract_driver_oracle_context(fuzz_driver)
        precondition_risk_context = _extract_precondition_risk_context(fuzz_driver)
        decisive_evidence_context = _extract_decisive_evidence_context(
            structured_summary=structured_summary,
            call_chain_context=call_chain_str,
            driver_oracle_context=driver_oracle_context,
            precondition_risk_context=precondition_risk_context,
        )
        fuzz_driver_error_patterns = _filter_error_patterns_for_prompt(
            fuzz_driver_error_patterns,
            precondition_risk_context=precondition_risk_context,
            source_kind="fuzz_driver",
        )
        api_error_patterns = _filter_error_patterns_for_prompt(
            api_error_patterns,
            precondition_risk_context=precondition_risk_context,
            source_kind="api",
        )
        fuzz_driver_t = _truncate(fuzz_driver, _MAX_SECTION_CHARS, "fuzz_driver")
        driver_oracle_context_t = _truncate(driver_oracle_context, _MAX_SECTION_CHARS, "driver_oracle_context")
        precondition_risk_context_t = _truncate(precondition_risk_context, _MAX_SECTION_CHARS, "precondition_risk_context")
        decisive_evidence_context_t = _truncate(decisive_evidence_context, _MAX_SECTION_CHARS, "decisive_evidence_context")
        api_info_t = _truncate(api_info, _MAX_SECTION_CHARS * 2, "api_source")
        raw_crash_t = _truncate(crash_info, _MAX_SECTION_CHARS, "raw_crash_info")
        cwe_t = _truncate(related_cwe_vulnerabilities, _MAX_SECTION_CHARS, "cwe_vulnerabilities")

        prompt_sections = dict(
            triage_label=triage_label,
            triage_confidence=triage_confidence,
            triage_evidence=triage_evidence_str,
            structured_crash_summary=structured_summary,
            call_chain_context=call_chain_str,
            runtime_context=runtime_str,
            fuzz_driver=fuzz_driver_t,
            driver_oracle_context=driver_oracle_context_t,
            precondition_risk_context=precondition_risk_context_t,
            decisive_evidence_context=decisive_evidence_context_t,
            api_info=api_info_t,
            fuzz_driver_error_patterns="\n".join(fuzz_driver_error_patterns[:20]),
            api_error_patterns="\n".join(api_error_patterns[:20]),
            related_cwe_vulnerabilities=cwe_t,
            raw_crash_info=raw_crash_t,
            init_crash=", ".join(self.init_crash),
            analysis_instructions=analysis_instructions,
        )

        # Build the enhanced prompt (same template for all ablation modes).
        # If the prompt is too long, shrink evidence sections but preserve the
        # final decision policy and JSON contract.
        question = _fit_prompt_preserving_instructions(
            _ENHANCED_CRASH_PROMPT,
            max_total_chars=_MAX_TOTAL_PROMPT_CHARS,
            required_instruction_text="Return exactly one valid JSON object",
            logger_label="Enhanced crash analysis prompt",
            **prompt_sections,
        )

        logger.info(
            "Enhanced Crash Analysis Question (length=%d, triage=%s, static=%s, runtime=%s, prompt=%s)",
            len(question), include_triage, include_static_context, include_runtime_context, prompt_variant,
        )

        response = self.llm.complete(question).text

        logger.info("Enhanced Crash Analysis Response:")
        logger.info(response)

        # Parse the primary response locally. A second LLM request is retained
        # only as a compatibility fallback for models that violate the JSON
        # contract, never as the normal decision path.
        enhanced_result = None
        decision_parse_mode = "primary_json"
        decision_parse_error = ""
        archive_metadata_repair = {
            "applied": False,
            "violation": "",
            "error": "",
        }
        negative_boundary_repair = {
            "applied": False,
            "violation": "",
            "error": "",
        }
        try:
            enhanced_result = _parse_enhanced_json_response(response)
        except Exception as e:
            decision_parse_mode = "legacy_second_pass"
            decision_parse_error = str(e)
            logger.warning(f"Primary structured response invalid; using legacy extraction fallback: {e}")
            try:
                extract_program = LLMTextCompletionProgram.from_defaults(
                    output_cls=EnhancedCrashAnalysis,
                    prompt_template_str=_ENHANCED_EXTRACT_PROMPT,
                    llm=self.llm,
                )
                enhanced_result = extract_program(raw_answer=response)
            except Exception as extract_error:
                decision_parse_mode = "basic_second_pass"
                decision_parse_error = f"{decision_parse_error}; enhanced fallback: {extract_error}"
                logger.warning(f"Failed to extract enhanced structured output: {extract_error}")

        if enhanced_result is not None:
            try:
                repaired_result, repair_response, violation = _repair_archive_metadata_consistency_with_llm(
                    self.llm,
                    prompt=question,
                    previous_response=response,
                    previous_result=enhanced_result,
                )
                if repair_response:
                    logger.warning(f"Archive metadata consistency repair applied: {violation}")
                    enhanced_result = repaired_result
                    response = repair_response
                    decision_parse_mode = f"{decision_parse_mode}+archive_metadata_repair"
                    archive_metadata_repair = {
                        "applied": True,
                        "violation": violation,
                        "error": "",
                    }
            except Exception as repair_error:
                logger.warning(f"Archive metadata consistency repair failed: {repair_error}")
                archive_metadata_repair = {
                    "applied": False,
                    "violation": _archive_metadata_consistency_violation(enhanced_result, question),
                    "error": str(repair_error),
                }
                decision_parse_error = (
                    f"{decision_parse_error}; archive metadata repair failed: {repair_error}"
                    if decision_parse_error
                    else f"archive metadata repair failed: {repair_error}"
                )

        if enhanced_result is not None:
            try:
                repaired_result, repair_response, violation = _repair_negative_boundary_consistency_with_llm(
                    self.llm,
                    prompt=question,
                    previous_response=response,
                    previous_result=enhanced_result,
                )
                if repair_response:
                    logger.warning(f"Negative boundary consistency repair applied: {violation}")
                    enhanced_result = repaired_result
                    response = repair_response
                    decision_parse_mode = f"{decision_parse_mode}+negative_boundary_repair"
                    negative_boundary_repair = {
                        "applied": True,
                        "violation": violation,
                        "error": "",
                    }
            except Exception as repair_error:
                logger.warning(f"Negative boundary consistency repair failed: {repair_error}")
                negative_boundary_repair = {
                    "applied": False,
                    "violation": _negative_boundary_consistency_violation(enhanced_result, question),
                    "error": str(repair_error),
                }
                decision_parse_error = (
                    f"{decision_parse_error}; negative boundary repair failed: {repair_error}"
                    if decision_parse_error
                    else f"negative boundary repair failed: {repair_error}"
                )

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
            except Exception as basic_error:
                decision_parse_mode = "triage_fallback"
                decision_parse_error = f"{decision_parse_error}; basic fallback: {basic_error}"
                is_api_bug = (triage_result or {}).get("label") == "likely_api_bug"
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
        enhanced_dict["_experiment_metadata"] = {
            "prompt_variant": prompt_variant,
            "differential_prompt_version": (
                "richer_differential_v4_20261027"
                if prompt_variant == "differential"
                else None
            ),
            "include_triage": include_triage,
            "include_static_context": include_static_context,
            "include_runtime_context": include_runtime_context,
            "prompt_chars": len(question),
            "prompt_sha256": hashlib.sha256(question.encode("utf-8", errors="replace")).hexdigest(),
            "decision_parse_mode": decision_parse_mode,
            "decision_parse_error": decision_parse_error,
            "archive_metadata_repair": archive_metadata_repair,
            "negative_boundary_repair": negative_boundary_repair,
        }
        if capture_prompt:
            enhanced_dict["_experiment_metadata"]["prompt"] = question

        return is_api_bug, crash_category, response, enhanced_dict
