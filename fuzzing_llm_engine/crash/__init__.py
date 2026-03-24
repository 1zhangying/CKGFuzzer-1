"""Enhanced crash analysis package.

Modules:
  sanitizer_parser  — Deterministic parsing of ASan/MSan/UBSan/LSan output
  triage            — Rule-based multi-stage crash pre-filtering
  locator           — Precise code location + call-chain context extraction
  debugger          — GDB-based dynamic crash reproduction & runtime context
  dedup             — Multi-level signature deduplication engine
  minimizer         — Delta debugging + libFuzzer test case minimization
  poc               — PoC file locating and copying
  report            — Structured crash report generation
"""

from .sanitizer_parser import parse_sanitizer_output, format_crash_summary
from .triage import triage_crash, compute_signatures
from .locator import locate_crash_site, format_call_chain_for_llm
from .debugger import reproduce_with_gdb, format_runtime_context_for_llm
from .dedup import DeduplicationEngine
from .minimizer import minimize_testcase
from .poc import locate_poc_on_host, safe_copy_poc
from .report import build_crash_report, save_crash_report

__all__ = [
    "parse_sanitizer_output",
    "format_crash_summary",
    "triage_crash",
    "compute_signatures",
    "locate_crash_site",
    "format_call_chain_for_llm",
    "reproduce_with_gdb",
    "format_runtime_context_for_llm",
    "DeduplicationEngine",
    "minimize_testcase",
    "locate_poc_on_host",
    "safe_copy_poc",
    "build_crash_report",
    "save_crash_report",
]
