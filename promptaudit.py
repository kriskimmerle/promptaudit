#!/usr/bin/env python3
"""promptaudit — LLM Prompt Injection & Security Scanner.

Zero-dependency static analysis tool that scans Python code for prompt
injection vulnerabilities, unsafe LLM output handling, and common
AI security antipatterns.

Usage:
    python promptaudit.py [path]            # Scan project
    python promptaudit.py --verbose         # Show details
    python promptaudit.py --json            # JSON output
    python promptaudit.py --check 80        # CI gate

Copyright 2026 Kris Kimmerle. MIT License.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


VERSION = "0.1.0"


# ── Constants ────────────────────────────────────────────────────────────────

# LLM client libraries and their call patterns
LLM_CLIENTS = {
    # OpenAI
    "openai": {"ChatCompletion", "Completion", "chat", "completions"},
    "OpenAI": {"chat", "completions", "create"},
    "AsyncOpenAI": {"chat", "completions", "create"},
    # Anthropic
    "anthropic": {"messages", "completions"},
    "Anthropic": {"messages", "create"},
    "AsyncAnthropic": {"messages", "create"},
    # LangChain
    "ChatOpenAI": {"invoke", "predict", "call"},
    "ChatAnthropic": {"invoke", "predict", "call"},
    "LLMChain": {"run", "invoke", "predict"},
    "ConversationChain": {"run", "invoke", "predict"},
    # Google
    "GenerativeModel": {"generate_content"},
    "genai": {"GenerativeModel", "generate_content"},
    # Cohere
    "cohere": {"chat", "generate"},
    # Hugging Face
    "pipeline": {"__call__"},
    "InferenceClient": {"text_generation", "chat_completion"},
}

# Import names that indicate LLM usage
LLM_IMPORTS = {
    "openai", "anthropic", "langchain", "langchain_openai",
    "langchain_anthropic", "langchain_community", "langchain_core",
    "google.generativeai", "genai", "cohere", "transformers",
    "huggingface_hub", "litellm", "llama_cpp", "ollama",
    "together", "groq", "mistralai",
}

# Dangerous functions to call on LLM output
DANGEROUS_OUTPUT_FUNCS = {
    "eval", "exec", "compile",
    "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.check_call",
    "pickle.loads", "yaml.load", "yaml.unsafe_load",
    "marshal.loads",
    "importlib.import_module", "__import__",
}

# Secret patterns near LLM code
SECRET_PATTERNS = [
    (r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9_-]{16,}["\']', "hardcoded API key"),
    (r'sk-[a-zA-Z0-9]{48}', "OpenAI API key"),
    (r'sk-proj-[a-zA-Z0-9_-]+', "OpenAI project key"),
    (r'sk-ant-[a-zA-Z0-9_-]+', "Anthropic API key"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    (r'Bearer\s+[a-zA-Z0-9_-]{20,}', "Bearer token"),
]


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A security finding."""
    rule: str
    severity: str  # critical, warning, info
    message: str
    file: str
    line: int
    detail: str = ""
    fix: str = ""


@dataclass
class FileResult:
    """Results for a single file."""
    path: str
    findings: list[Finding] = field(default_factory=list)
    has_llm_usage: bool = False


@dataclass
class Report:
    """Full scan report."""
    path: str
    files_scanned: int = 0
    files_with_llm: int = 0
    files_with_issues: int = 0
    results: list[FileResult] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.results for f in r.findings if f.severity == "critical")

    @property
    def warning_count(self) -> int:
        return sum(1 for r in self.results for f in r.findings if f.severity == "warning")

    @property
    def score(self) -> float:
        if self.files_with_llm == 0:
            return 100.0
        penalty = 0.0
        for r in self.results:
            for f in r.findings:
                if f.severity == "critical":
                    penalty += 10
                elif f.severity == "warning":
                    penalty += 3
                else:
                    penalty += 1
        return round(max(0.0, 100.0 - penalty), 1)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 95:
            return "A+"
        elif s >= 90:
            return "A"
        elif s >= 80:
            return "B"
        elif s >= 70:
            return "C"
        elif s >= 60:
            return "D"
        else:
            return "F"


# ── AST helpers ──────────────────────────────────────────────────────────────

def _get_call_name(node: ast.Call) -> str | None:
    """Get dotted name from a Call node."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    elif isinstance(func, ast.Attribute):
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


def _get_attr_name(node: ast.Attribute) -> str | None:
    """Get dotted name from an Attribute node."""
    parts = [node.attr]
    current = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _contains_format(node: ast.AST) -> bool:
    """Check if a node contains string formatting (f-string, .format, %)."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call):
        name = _get_call_name(node)
        if name and name.endswith(".format"):
            return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    # Check children
    for child in ast.iter_child_nodes(node):
        if _contains_format(child):
            return True
    return False


def _has_user_input_ref(node: ast.AST, user_vars: set[str]) -> bool:
    """Check if node references user-input variables."""
    if isinstance(node, ast.Name) and node.id in user_vars:
        return True
    for child in ast.iter_child_nodes(node):
        if _has_user_input_ref(child, user_vars):
            return True
    return False


def _is_string_concat(node: ast.AST) -> bool:
    """Check if node is string concatenation with +."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    return False


# ── Checker ──────────────────────────────────────────────────────────────────

class PromptAuditor:
    """Scans a Python file for LLM security issues."""

    def __init__(self, filepath: str, source: str):
        self.filepath = filepath
        self.source = source
        self.findings: list[Finding] = []
        self.imports: dict[str, str] = {}
        self.has_llm_usage = False
        self.user_input_vars: set[str] = set()

    def audit(self) -> tuple[list[Finding], bool]:
        """Run all checks. Returns (findings, has_llm_usage)."""
        try:
            tree = ast.parse(self.source, filename=self.filepath)
        except SyntaxError:
            return [], False

        # Phase 1: Detect LLM usage
        self._collect_imports(tree)
        self.has_llm_usage = self._detect_llm_usage(tree)

        if not self.has_llm_usage:
            return [], False

        # Phase 2: Detect user input variables
        self._detect_user_input_vars(tree)

        # Phase 3: Run security checks
        self._check_prompt_injection(tree)
        self._check_unsafe_output(tree)
        self._check_hardcoded_secrets(tree)
        self._check_system_prompt_exposure(tree)
        self._check_missing_output_validation(tree)
        self._check_dangerous_tools(tree)

        return self.findings, True

    def _collect_imports(self, tree: ast.Module) -> None:
        """Build import alias map."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.imports[name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.imports[name] = f"{module}.{alias.name}" if module else alias.name

    def _detect_llm_usage(self, tree: ast.Module) -> bool:
        """Detect if file uses LLM libraries."""
        # Check imports
        for alias, full_name in self.imports.items():
            for llm_lib in LLM_IMPORTS:
                if full_name.startswith(llm_lib) or alias in LLM_CLIENTS:
                    return True

        # Check for string patterns suggesting LLM usage
        source_lower = self.source.lower()
        llm_keywords = [
            "openai", "anthropic", "langchain", "llm", "chatgpt",
            "gpt-4", "gpt-3", "claude", "gemini", "prompt",
            "completion", "chat_completion", "generate_content",
            "system_prompt", "user_prompt",
        ]
        matches = sum(1 for kw in llm_keywords if kw in source_lower)
        return matches >= 2  # At least 2 LLM-related keywords

    def _detect_user_input_vars(self, tree: ast.Module) -> None:
        """Find variables that likely contain user input."""
        user_patterns = {
            "user_input", "user_message", "user_query", "user_prompt",
            "query", "question", "message", "prompt", "input_text",
            "request", "user_text", "content", "text",
        }

        for node in ast.walk(tree):
            # Function parameters
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args:
                    if arg.arg in user_patterns or arg.arg.startswith("user"):
                        self.user_input_vars.add(arg.arg)

            # Assignments from input() or request
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        if name in user_patterns or name.startswith("user"):
                            self.user_input_vars.add(name)

                        # input() calls
                        if isinstance(node.value, ast.Call):
                            call_name = _get_call_name(node.value)
                            if call_name == "input":
                                self.user_input_vars.add(name)

    def _check_prompt_injection(self, tree: ast.Module) -> None:
        """P01: Detect unsanitized user input in prompts."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _get_call_name(node)
            if call_name is None:
                continue

            # Check if this is an LLM API call
            is_llm_call = False
            for client, methods in LLM_CLIENTS.items():
                if call_name.endswith(".create") or call_name.endswith(".invoke"):
                    is_llm_call = True
                    break
                for method in methods:
                    if method in call_name:
                        is_llm_call = True
                        break

            if not is_llm_call:
                continue

            # Check arguments for formatted strings with user input
            for arg in node.args:
                if _contains_format(arg):
                    if _has_user_input_ref(arg, self.user_input_vars):
                        self._add(
                            "P01", "critical",
                            "User input directly in LLM API call argument",
                            node,
                            "User input is formatted directly into a prompt "
                            "without sanitization, enabling prompt injection.",
                            "Sanitize user input or use a prompt template with "
                            "proper escaping.",
                        )

            # Check keyword arguments
            for kw in node.keywords:
                if kw.arg in ("content", "messages", "prompt", "text",
                              "system", "input"):
                    if _contains_format(kw.value):
                        if _has_user_input_ref(kw.value, self.user_input_vars):
                            self._add(
                                "P01", "critical",
                                f"User input formatted into '{kw.arg}' parameter",
                                node,
                                f"User input is interpolated into the '{kw.arg}' "
                                f"parameter of an LLM call.",
                                "Use input validation, escaping, or a structured "
                                "prompt template.",
                            )

        # Also check string assignments that look like prompts
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id.lower()
                    if any(kw in name for kw in ("prompt", "system", "template",
                                                  "instruction")):
                        if _contains_format(node.value):
                            if _has_user_input_ref(node.value, self.user_input_vars):
                                self._add(
                                    "P01", "warning",
                                    f"User input in prompt variable: {target.id}",
                                    node,
                                    "Variable that appears to be a prompt template "
                                    "contains formatted user input.",
                                    "Separate system instructions from user input.",
                                )

    def _check_unsafe_output(self, tree: ast.Module) -> None:
        """P02: Detect unsafe handling of LLM output."""
        # Find variables that store LLM responses
        response_vars: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    call_name = _get_call_name(node.value)
                    if call_name:
                        for client, methods in LLM_CLIENTS.items():
                            if any(m in call_name for m in methods):
                                for target in node.targets:
                                    if isinstance(target, ast.Name):
                                        response_vars.add(target.id)
                                break

            # Also common patterns like response.choices[0].message.content
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(kw in name for kw in ("response", "result",
                                                      "output", "completion",
                                                      "answer", "reply")):
                            response_vars.add(target.id)

        # Check if response vars are passed to dangerous functions
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _get_call_name(node)
            if call_name is None:
                continue

            resolved = self.imports.get(call_name.split(".")[0], call_name)
            full_name = call_name

            if full_name in DANGEROUS_OUTPUT_FUNCS or resolved in DANGEROUS_OUTPUT_FUNCS:
                # Check if any argument references a response var
                for arg in node.args:
                    if _has_user_input_ref(arg, response_vars):
                        self._add(
                            "P02", "critical",
                            f"LLM output passed to dangerous function: {full_name}()",
                            node,
                            f"LLM output is passed to {full_name}() which can "
                            f"execute arbitrary code. This is a code injection "
                            f"vulnerability.",
                            f"Never pass LLM output to {full_name}(). Parse and "
                            f"validate the output first.",
                        )

                for kw in node.keywords:
                    if _has_user_input_ref(kw.value, response_vars):
                        self._add(
                            "P02", "critical",
                            f"LLM output in {full_name}() keyword argument",
                            node,
                            "LLM output used as argument to dangerous function.",
                            f"Validate and sanitize LLM output before passing to "
                            f"{full_name}().",
                        )

    def _check_hardcoded_secrets(self, tree: ast.Module) -> None:
        """P03: Detect hardcoded API keys near LLM code."""
        for pattern, label in SECRET_PATTERNS:
            for match in re.finditer(pattern, self.source):
                line_num = self.source[:match.start()].count("\n") + 1
                self._add(
                    "P03", "critical",
                    f"Hardcoded {label} detected",
                    ast.Module(body=[], type_ignores=[]),
                    f"Found {label} pattern at line {line_num}. "
                    f"Use environment variables instead.",
                    "Use os.environ['API_KEY'] or a secrets manager.",
                    line_override=line_num,
                )

    def _check_system_prompt_exposure(self, tree: ast.Module) -> None:
        """P04: Detect system prompts that might leak."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue

            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue

                name = target.id.lower()
                if "system" not in name and "instruction" not in name:
                    continue

                # Check if the system prompt is a plain string (logged/exposed)
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    prompt_val = node.value.value
                    # Check for common anti-patterns in system prompts
                    if any(kw in prompt_val.lower() for kw in [
                        "you are", "your role", "you must",
                        "do not reveal", "keep secret",
                        "ignore previous", "override",
                    ]):
                        # Check if it contains instructions about secrecy
                        if any(kw in prompt_val.lower() for kw in [
                            "do not reveal", "keep secret", "don't share",
                            "never disclose", "confidential",
                        ]):
                            self._add(
                                "P04", "warning",
                                f"System prompt relies on secrecy: {target.id}",
                                node,
                                "System prompt contains secrecy instructions. "
                                "Relying on the LLM to keep secrets is unreliable — "
                                "prompt extraction attacks can bypass these.",
                                "Don't put secrets in prompts. Use server-side "
                                "validation instead.",
                            )

    def _check_missing_output_validation(self, tree: ast.Module) -> None:
        """P05: Detect LLM output used without validation."""
        # Find LLM response assignments
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue

            if not isinstance(node.value, ast.Call):
                continue

            call_name = _get_call_name(node.value)
            if call_name is None:
                continue

            is_llm_call = any(
                any(m in call_name for m in methods)
                for methods in LLM_CLIENTS.values()
            )
            if not is_llm_call:
                continue

            # Check if the response is used in a return or passed to another
            # function without any validation
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    # Search for direct return of the variable
                    func_node = self._find_parent_func(node, tree)
                    if func_node:
                        for child in ast.walk(func_node):
                            if isinstance(child, ast.Return):
                                if isinstance(child.value, ast.Name) and child.value.id == var_name:
                                    self._add(
                                        "P05", "info",
                                        f"LLM response returned without validation: {var_name}",
                                        child,
                                        "LLM output is returned directly without "
                                        "validation or sanitization.",
                                        "Add output validation (type checking, "
                                        "content filtering, length limits).",
                                    )

    def _check_dangerous_tools(self, tree: ast.Module) -> None:
        """P06: Detect patterns where LLMs can trigger dangerous actions."""
        # Look for tool/function definitions used with LLM agents
        tool_decorators = {
            "tool", "function_tool", "register_tool",
            "langchain.tools.tool", "agent.tool",
        }

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            is_tool = False
            for dec in node.decorator_list:
                if isinstance(dec, ast.Name) and dec.id in tool_decorators:
                    is_tool = True
                elif isinstance(dec, ast.Call):
                    dec_name = _get_call_name(dec)
                    if dec_name and dec_name in tool_decorators:
                        is_tool = True
                elif isinstance(dec, ast.Attribute):
                    attr_name = _get_attr_name(dec)
                    if attr_name and attr_name in tool_decorators:
                        is_tool = True

            if not is_tool:
                continue

            # Check if the tool function contains dangerous operations
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = _get_call_name(child)
                    if call_name in DANGEROUS_OUTPUT_FUNCS:
                        self._add(
                            "P06", "critical",
                            f"Dangerous operation in LLM tool: {node.name}() "
                            f"calls {call_name}()",
                            child,
                            f"LLM tool function {node.name}() contains "
                            f"{call_name}() which can execute arbitrary code. "
                            f"An adversarial prompt could exploit this.",
                            "Add strict input validation and sandboxing to "
                            "tool functions.",
                        )

    def _find_parent_func(self, target: ast.AST, tree: ast.Module) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        """Find the function containing a node."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if child is target:
                        return node
        return None

    def _add(self, rule: str, severity: str, message: str,
             node: ast.AST, detail: str = "", fix: str = "",
             line_override: int | None = None) -> None:
        line = line_override or getattr(node, "lineno", 0)
        self.findings.append(Finding(
            rule=rule, severity=severity, message=message,
            file=self.filepath, line=line, detail=detail, fix=fix,
        ))


# ── Project scanner ──────────────────────────────────────────────────────────

IGNORE_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".tox", ".nox", ".eggs", "node_modules", ".venv", "venv",
    "env", ".env", "build", "dist", ".ruff_cache",
}


def find_python_files(root: Path) -> list[Path]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
        for f in filenames:
            if f.endswith(".py"):
                files.append(Path(dirpath) / f)
    files.sort()
    return files


def scan_project(path: str, severity_filter: str | None = None) -> Report:
    """Scan a project for LLM security issues."""
    root = Path(path).resolve()
    report = Report(path=str(root))

    if root.is_file() and root.suffix == ".py":
        files = [root]
    elif root.is_dir():
        files = find_python_files(root)
    else:
        print(f"Error: {root} is not a Python file or directory", file=sys.stderr)
        sys.exit(1)

    for filepath in files:
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel_path = str(filepath.relative_to(root)) if root.is_dir() else filepath.name
        auditor = PromptAuditor(rel_path, source)
        findings, has_llm = auditor.audit()

        if severity_filter:
            sev_order = {"critical": 0, "warning": 1, "info": 2}
            min_level = sev_order.get(severity_filter, 2)
            findings = [f for f in findings if sev_order.get(f.severity, 2) <= min_level]

        result = FileResult(path=rel_path, findings=findings, has_llm_usage=has_llm)
        report.files_scanned += 1
        if has_llm:
            report.files_with_llm += 1
        if findings:
            report.files_with_issues += 1
        report.results.append(result)

    return report


# ── Output formatting ────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "\033[91m",
    "warning": "\033[93m",
    "info": "\033[90m",
}
SEVERITY_ICONS = {
    "critical": "🔴",
    "warning": "🟡",
    "info": "⚪",
}
GRADE_COLORS = {
    "A+": "\033[92m", "A": "\033[92m",
    "B": "\033[93m", "C": "\033[93m",
    "D": "\033[91m", "F": "\033[91m",
}
RESET = "\033[0m"

RULE_DESCRIPTIONS = {
    "P01": "Prompt injection (unsanitized user input in prompts)",
    "P02": "Unsafe LLM output handling (eval/exec/subprocess)",
    "P03": "Hardcoded API key/secret",
    "P04": "System prompt secrecy reliance",
    "P05": "Missing output validation",
    "P06": "Dangerous operation in LLM tool function",
}


def format_text(report: Report, verbose: bool = False) -> str:
    lines = []
    lines.append("")
    lines.append(f"  promptaudit — LLM Prompt Security Scanner")
    lines.append(f"  {'─' * 45}")
    lines.append(f"  Project: {report.path}")
    lines.append("")

    color = GRADE_COLORS.get(report.grade, "")
    lines.append(f"  Score: {color}{report.score}/100 ({report.grade}){RESET}")
    lines.append(f"  Files: {report.files_scanned} scanned, "
                 f"{report.files_with_llm} with LLM usage, "
                 f"{report.files_with_issues} with issues")
    lines.append(f"  Findings: {report.total_findings} "
                 f"({report.critical_count} critical, "
                 f"{report.warning_count} warnings)")
    lines.append("")

    if report.total_findings == 0:
        if report.files_with_llm == 0:
            lines.append(f"  ℹ️  No LLM usage detected in this project.")
        else:
            lines.append(f"  ✅ No security issues found in LLM code!")
        lines.append("")
        return "\n".join(lines)

    for result in report.results:
        if not result.findings and not verbose:
            continue
        if not result.has_llm_usage and not verbose:
            continue

        lines.append(f"  📄 {result.path}")
        if not result.findings:
            lines.append(f"    ✅ Clean")
            lines.append("")
            continue

        for f in sorted(result.findings, key=lambda x: x.line):
            icon = SEVERITY_ICONS.get(f.severity, "⚪")
            sev_color = SEVERITY_COLORS.get(f.severity, "")
            lines.append(
                f"    {icon} {sev_color}L{f.line:>4} [{f.rule}] {f.message}{RESET}"
            )
            if verbose:
                if f.detail:
                    lines.append(f"         {f.detail}")
                if f.fix:
                    lines.append(f"         💡 {f.fix}")
        lines.append("")

    # Rule summary
    rule_counts: dict[str, int] = {}
    for r in report.results:
        for f in r.findings:
            rule_counts[f.rule] = rule_counts.get(f.rule, 0) + 1

    if rule_counts:
        lines.append(f"  Rules:")
        lines.append(f"  {'─' * 45}")
        for rule, count in sorted(rule_counts.items()):
            desc = RULE_DESCRIPTIONS.get(rule, "Unknown")
            lines.append(f"    {rule}: {count}× — {desc}")
        lines.append("")

    return "\n".join(lines)


def format_json(report: Report) -> str:
    data = {
        "path": report.path,
        "score": report.score,
        "grade": report.grade,
        "files_scanned": report.files_scanned,
        "files_with_llm": report.files_with_llm,
        "files_with_issues": report.files_with_issues,
        "total_findings": report.total_findings,
        "critical_count": report.critical_count,
        "warning_count": report.warning_count,
        "files": [],
    }
    for r in report.results:
        if r.findings:
            data["files"].append({
                "path": r.path,
                "has_llm_usage": r.has_llm_usage,
                "findings": [
                    {
                        "rule": f.rule,
                        "severity": f.severity,
                        "message": f.message,
                        "line": f.line,
                        "detail": f.detail,
                        "fix": f.fix,
                    }
                    for f in r.findings
                ],
            })
    return json.dumps(data, indent=2)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="promptaudit",
        description="LLM Prompt Injection & Security Scanner — find prompt "
                    "injection, unsafe output handling, and AI security issues",
    )
    parser.add_argument("path", nargs="?", default=".",
                        help="Python file or project directory (default: .)")
    parser.add_argument("--severity", "-s",
                        choices=["critical", "warning", "info"],
                        help="Minimum severity to report")
    parser.add_argument("--json", "-j", action="store_true",
                        help="JSON output")
    parser.add_argument("--check", "-c", type=float, metavar="THRESHOLD",
                        help="Exit 1 if score < threshold (CI mode)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show details and fix suggestions")
    parser.add_argument("--version", "-V", action="version",
                        version=f"promptaudit {VERSION}")

    args = parser.parse_args()

    report = scan_project(args.path, severity_filter=args.severity)

    if args.json:
        print(format_json(report))
    else:
        print(format_text(report, verbose=args.verbose))

    if args.check is not None:
        if report.score < args.check:
            print(f"  ❌ Score {report.score} below threshold {args.check}",
                  file=sys.stderr)
            sys.exit(1)
        else:
            print(f"  ✅ Score {report.score} meets threshold {args.check}",
                  file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
