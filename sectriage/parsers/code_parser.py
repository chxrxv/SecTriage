"""Lightweight static source-code scanner.

This is intentionally a *pattern* scanner, not a full data-flow/taint analyzer:
matches are line-based regexes (plus a small Python AST pass for a few
high-confidence dangerous calls). It trades recall for speed and zero setup —
it will miss vulnerabilities that are split across multiple lines or built up
through several variable assignments. Every finding gets a precise file+line
citation so the LLM analyzer (and a human) can go straight to the code.

Supported languages: Python, JavaScript/TypeScript, Java, Go.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass

from ..models import Finding, Severity, SourceTool

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".mypy_cache", ".pytest_cache", "vendor", "target", ".idea", ".vscode",
}

_EXTENSION_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".go": "go",
}

ALL_LANGUAGES = set(_EXTENSION_LANGUAGE.values())


@dataclass(frozen=True)
class Rule:
    id: str
    vuln_pattern: str
    severity: Severity
    message: str
    pattern: re.Pattern
    languages: frozenset[str] | None = None  # None = applies to every supported language


def _rule(id_, vuln_pattern, severity, message, regex, languages=None, flags=0):
    return Rule(
        id=id_,
        vuln_pattern=vuln_pattern,
        severity=severity,
        message=message,
        pattern=re.compile(regex, flags),
        languages=frozenset(languages) if languages else None,
    )


RULES: list[Rule] = [
    # ---- Hardcoded secrets (language-agnostic) ----------------------------
    _rule(
        "hardcoded-secret-assignment", "hardcoded_secret", Severity.HIGH,
        "Hardcoded credential assigned as a literal string",
        # No leading \b: variable names are often prefixed (STRIPE_API_KEY), and since
        # "_"/letters form one contiguous \w run, a boundary would never appear right
        # before "api_key" in that case. re.search() finds the keyword as a substring
        # instead, then requires it to be immediately followed by `= "literal"`.
        r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?key|auth[_-]?token|password|passwd|pwd|secret)\s*[:=]\s*["\']([^"\'\s]{8,})["\']',
    ),
    _rule(
        "aws-access-key-id", "hardcoded_secret", Severity.CRITICAL,
        "Hardcoded AWS access key ID",
        r'AKIA[0-9A-Z]{16}',
    ),
    _rule(
        "private-key-block", "hardcoded_secret", Severity.CRITICAL,
        "Embedded private key material",
        r'-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----',
    ),

    # ---- SQL injection ------------------------------------------------------
    _rule(
        "sqli-python-fstring", "sql_injection", Severity.CRITICAL,
        "SQL query built with an f-string / string interpolation instead of parameters",
        r'\.\s*execute\s*\(\s*f["\']',
        languages={"python"},
    ),
    _rule(
        "sqli-python-concat", "sql_injection", Severity.CRITICAL,
        "SQL query built with string concatenation instead of parameters",
        r'\.\s*execute\s*\(\s*["\'][^"\']*["\']\s*\+',
        languages={"python"},
    ),
    _rule(
        "sqli-python-percent", "sql_injection", Severity.HIGH,
        "SQL query built with %-formatting instead of parameterized query",
        r'\.\s*execute\s*\([^)]*%\s*\(',
        languages={"python"},
    ),
    _rule(
        "sqli-js-template-literal", "sql_injection", Severity.CRITICAL,
        "SQL query built with a template literal instead of a parameterized query",
        r'\.\s*(query|execute)\s*\(\s*`[^`]*\$\{',
        languages={"javascript"},
    ),
    _rule(
        "sqli-js-concat", "sql_injection", Severity.CRITICAL,
        "SQL query built with string concatenation instead of a parameterized query",
        r'\.\s*(query|execute)\s*\(\s*["\'][^"\']*["\']\s*\+',
        languages={"javascript"},
    ),
    _rule(
        "sqli-java-concat", "sql_injection", Severity.CRITICAL,
        "SQL executed via Statement with string concatenation instead of PreparedStatement",
        r'\.\s*(execute|executeQuery|executeUpdate)\s*\(\s*["\'][^"\']*["\']\s*\+',
        languages={"java"},
    ),
    _rule(
        "sqli-go-sprintf", "sql_injection", Severity.CRITICAL,
        "SQL query built with fmt.Sprintf instead of a parameterized query",
        r'\.\s*(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf',
        languages={"go"},
    ),

    # ---- Cross-site scripting ------------------------------------------------
    _rule(
        "xss-python-string-concat-html", "xss", Severity.HIGH,
        "HTML response built from unescaped user input via string concatenation",
        r'return\s+["\'][^"\']*<[a-zA-Z]+[^"\']*["\']\s*\+',
        languages={"python"},
    ),
    _rule(
        "xss-python-jinja-safe-filter", "xss", Severity.MEDIUM,
        "Jinja `|safe` filter disables autoescaping for this value",
        r'\{\{.*\|\s*safe\s*\}\}',
        languages={"python"},
    ),
    _rule(
        "xss-js-innerhtml", "xss", Severity.HIGH,
        "Untrusted value assigned directly to innerHTML",
        r'\.innerHTML\s*=\s*[^"\'`;]',
        languages={"javascript"},
    ),
    _rule(
        "xss-js-document-write", "xss", Severity.HIGH,
        "document.write() called with a variable (potential DOM XSS sink)",
        r'document\.write\s*\(\s*[a-zA-Z_$][\w$]*\s*\)',
        languages={"javascript"},
    ),
    _rule(
        "xss-react-dangerously-set", "xss", Severity.MEDIUM,
        "dangerouslySetInnerHTML used — verify the HTML is sanitized",
        r'dangerouslySetInnerHTML',
        languages={"javascript"},
    ),

    # ---- Insecure deserialization ---------------------------------------
    _rule(
        "insecure-deser-python-pickle", "insecure_deserialization", Severity.CRITICAL,
        "pickle.load/loads() on data that may originate from an untrusted source",
        r'pickle\.loads?\s*\(',
        languages={"python"},
    ),
    _rule(
        "insecure-deser-python-yaml", "insecure_deserialization", Severity.HIGH,
        "yaml.load() without a SafeLoader can execute arbitrary code",
        r'yaml\.load\s*\((?!.*SafeLoader)',
        languages={"python"},
    ),
    _rule(
        "insecure-deser-js-eval", "insecure_deserialization", Severity.CRITICAL,
        "eval() on data that may originate from an untrusted source",
        r'\beval\s*\(',
        languages={"javascript"},
    ),
    _rule(
        "insecure-deser-java-readobject", "insecure_deserialization", Severity.CRITICAL,
        "ObjectInputStream.readObject() deserializes untrusted data unsafely",
        r'readObject\s*\(\s*\)',
        languages={"java"},
    ),

    # ---- SSRF ---------------------------------------------------------------
    _rule(
        "ssrf-python-requests", "ssrf", Severity.HIGH,
        "Outbound HTTP request built from user-controlled input with no allowlist check",
        r'requests\.(get|post|put|delete|head)\s*\(\s*[a-zA-Z_][\w.]*\s*[),]',
        languages={"python"},
    ),
    _rule(
        "ssrf-js-fetch-axios", "ssrf", Severity.HIGH,
        "Outbound HTTP request built from user-controlled input with no allowlist check",
        r'(fetch|axios\.(get|post))\s*\(\s*[a-zA-Z_$][\w$.]*\s*[),]',
        languages={"javascript"},
    ),
    _rule(
        "ssrf-go-http-get", "ssrf", Severity.HIGH,
        "Outbound HTTP request built from user-controlled input with no allowlist check",
        r'http\.Get\s*\(\s*[a-zA-Z_][\w.]*\s*\)',
        languages={"go"},
    ),

    # ---- Path traversal -------------------------------------------------
    _rule(
        "path-traversal-python-open", "path_traversal", Severity.HIGH,
        "File path built from user input without sanitization (e.g. secure_filename)",
        r'(open|send_file)\s*\(\s*(os\.path\.join\([^)]*request\.|.*request\.(args|form|values)\[)',
        languages={"python"},
    ),
    _rule(
        "path-traversal-js-fs", "path_traversal", Severity.HIGH,
        "File path built directly from request input without sanitization",
        r'fs\.(readFile|readFileSync|createReadStream)\s*\(\s*[^)]*req\.(params|query|body)',
        languages={"javascript"},
    ),
    _rule(
        "path-traversal-java-file", "path_traversal", Severity.HIGH,
        "File path built directly from request parameter without sanitization",
        r'new\s+File\s*\([^)]*getParameter\s*\(',
        languages={"java"},
    ),
    _rule(
        "path-traversal-go-open", "path_traversal", Severity.HIGH,
        "File path built directly from request input without sanitization",
        r'os\.Open\s*\([^)]*r\.URL\.Query',
        languages={"go"},
    ),
]

# Dangerous Python calls checked via AST (fewer false positives than regex for these).
_PY_DANGEROUS_CALLS = {
    "eval": ("code_injection", Severity.CRITICAL, "eval() executes arbitrary code from its argument"),
    "exec": ("code_injection", Severity.CRITICAL, "exec() executes arbitrary code from its argument"),
    "os.system": ("command_injection", Severity.CRITICAL, "os.system() with unsanitized input allows command injection"),
    "marshal.loads": ("insecure_deserialization", Severity.HIGH, "marshal.loads() on untrusted data can execute arbitrary code"),
}

_MISSING_AUTH_ROUTE_RE = re.compile(r'@app\.route\s*\(\s*["\']([^"\']*)["\']')
_SENSITIVE_ROUTE_HINTS = ("admin", "delete", "update", "settings", "account", "user", "config", "internal")
_AUTH_DECORATOR_HINT_RE = re.compile(r'login_required|requires_auth|auth_required|@jwt_required|permission_required', re.IGNORECASE)


def scan_codebase(root_dir: str) -> list[Finding]:
    findings: list[Finding] = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]

        for filename in filenames:
            ext = os.path.splitext(filename)[1]
            language = _EXTENSION_LANGUAGE.get(ext)
            if language is None:
                continue

            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, root_dir)

            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    source = f.read()
            except OSError:
                continue

            lines = source.splitlines()
            findings.extend(_apply_line_rules(rel_path, lines, language))
            findings.extend(_apply_missing_auth_heuristic(rel_path, lines, language))

            if language == "python":
                findings.extend(_python_ast_checks(rel_path, source))

    return findings


def _apply_line_rules(rel_path: str, lines: list[str], language: str) -> list[Finding]:
    findings = []
    for rule in RULES:
        if rule.languages is not None and language not in rule.languages:
            continue
        for lineno, line in enumerate(lines, start=1):
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        source_tool=SourceTool.CODE_REVIEW,
                        severity=rule.severity,
                        description=rule.message,
                        affected_asset=f"{rel_path}:{lineno}",
                        raw_evidence=line.strip()[:300],
                        file_path=rel_path,
                        line_number=lineno,
                        vuln_pattern=rule.vuln_pattern,
                    )
                )
    return findings


def _apply_missing_auth_heuristic(rel_path: str, lines: list[str], language: str) -> list[Finding]:
    """Flask-specific heuristic: a route whose path looks sensitive with no auth
    decorator in the few lines immediately above it. Low-confidence by design —
    the LLM analyzer and a human reviewer should confirm before acting on it."""
    if language != "python":
        return []

    findings = []
    for lineno, line in enumerate(lines, start=1):
        m = _MISSING_AUTH_ROUTE_RE.search(line)
        if not m:
            continue
        route_path = m.group(1)
        if not any(hint in route_path.lower() for hint in _SENSITIVE_ROUTE_HINTS):
            continue

        context_start = max(0, lineno - 4)
        context = "\n".join(lines[context_start:lineno + 1])
        if _AUTH_DECORATOR_HINT_RE.search(context):
            continue

        findings.append(
            Finding(
                source_tool=SourceTool.CODE_REVIEW,
                severity=Severity.MEDIUM,
                description=f"Route '{route_path}' looks sensitive but has no auth decorator above it (heuristic — verify manually)",
                affected_asset=f"{rel_path}:{lineno}",
                raw_evidence=line.strip()[:300],
                file_path=rel_path,
                line_number=lineno,
                vuln_pattern="missing_auth_check",
            )
        )
    return findings


def _python_ast_checks(rel_path: str, source: str) -> list[Finding]:
    findings = []
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _dotted_call_name(node.func)
        if call_name in _PY_DANGEROUS_CALLS:
            vuln_pattern, severity, message = _PY_DANGEROUS_CALLS[call_name]
            findings.append(
                Finding(
                    source_tool=SourceTool.CODE_REVIEW,
                    severity=severity,
                    description=message,
                    affected_asset=f"{rel_path}:{node.lineno}",
                    raw_evidence=ast.get_source_segment(source, node) or call_name,
                    file_path=rel_path,
                    line_number=node.lineno,
                    vuln_pattern=vuln_pattern,
                )
            )
    return findings


def _dotted_call_name(func_node: ast.expr) -> str | None:
    if isinstance(func_node, ast.Name):
        return func_node.id
    if isinstance(func_node, ast.Attribute):
        base = _dotted_call_name(func_node.value)
        return f"{base}.{func_node.attr}" if base else func_node.attr
    return None
