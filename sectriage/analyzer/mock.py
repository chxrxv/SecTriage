"""Deterministic mock analyzer — zero cost, no network, no API key required.

Used as the default so the full pipeline (parse -> triage -> dedup -> report)
can be exercised and demoed for free. It approximates what an LLM triage call
would produce using the same vuln_pattern taxonomy the code scanner already
assigns, plus keyword heuristics for scanner-sourced findings, so accuracy
metrics computed against the mock analyzer are meaningful (not just plumbing
tests) even though they understate what the real model can do with nuanced,
free-text evidence it hasn't seen a fixed rule for.
"""
from __future__ import annotations

import random
import time

from ..models import Finding, Priority, Severity, TriageResult

_VULN_PATTERN_TO_OWASP = {
    "sql_injection": "A03:2021-Injection",
    "xss": "A03:2021-Injection",
    "command_injection": "A03:2021-Injection",
    "code_injection": "A03:2021-Injection",
    "hardcoded_secret": "A07:2021-Identification and Authentication Failures",
    "insecure_deserialization": "A08:2021-Software and Data Integrity Failures",
    "ssrf": "A10:2021-Server-Side Request Forgery (SSRF)",
    "path_traversal": "A01:2021-Broken Access Control",
    "missing_auth_check": "A01:2021-Broken Access Control",
}

_REMEDIATION_TEMPLATES = {
    "sql_injection": "Replace the string-built query with a parameterized query / prepared statement so user input is never concatenated into SQL text.",
    "xss": "Escape or sanitize the value before rendering it (use the template engine's autoescaping, or a sanitizer library), and avoid raw HTML sinks like innerHTML/document.write for untrusted data.",
    "command_injection": "Avoid shell=True / os.system with interpolated input; use the subprocess argument-list form and validate input against an allowlist.",
    "code_injection": "Never pass user-controlled input to eval()/exec(); replace with a safe, restricted parser (e.g. ast.literal_eval for literals, or a proper expression-evaluation library) that cannot execute arbitrary code.",
    "hardcoded_secret": "Remove the literal credential from source, rotate it immediately (it is likely already compromised via version control history), and load it from an environment variable or secrets manager at runtime.",
    "insecure_deserialization": "Avoid deserializing data from untrusted sources with pickle/yaml.load/eval; use a safe format (JSON) or a safe loader (yaml.safe_load) with strict schema validation.",
    "ssrf": "Validate and allowlist the destination host/IP before making the outbound request; block requests to internal/link-local address ranges.",
    "path_traversal": "Sanitize the filename (e.g. werkzeug.utils.secure_filename) and resolve the final path, then verify it is still inside the intended root directory before opening it.",
    "missing_auth_check": "Add the project's auth decorator/middleware to this route and add a regression test asserting unauthenticated requests are rejected.",
}

_GENERIC_REMEDIATION = "Review the finding evidence and apply the fix recommended by the source tool; re-scan to confirm the finding no longer reproduces."

_KEYWORD_OWASP_HINTS = [
    (("sql injection", "sqli"), "A03:2021-Injection"),
    (("cross site scripting", "xss"), "A03:2021-Injection"),
    (("csrf", "cross site request forgery"), "A01:2021-Broken Access Control"),
    (("ssl", "tls", "certificate", "weak cipher"), "A02:2021-Cryptographic Failures"),
    (("outdated", "vulnerable", "cve-", "out of date"), "A06:2021-Vulnerable and Outdated Components"),
    (("directory listing", "misconfigur", "default credential", "debug mode"), "A05:2021-Security Misconfiguration"),
    (("authentication", "session fixation", "weak password"), "A07:2021-Identification and Authentication Failures"),
    (("open port", "telnet", "ftp", "smb"), "A05:2021-Security Misconfiguration"),
]


def mock_triage(finding: Finding, context: str, simulate_latency: bool = True) -> tuple[TriageResult, dict]:
    """Return a (TriageResult, stats-dict) pair with the same shape a real LLM call
    would produce. `simulate_latency` adds a small artificial delay so demo timing
    numbers aren't literally instant — it is NOT a substitute for measuring real
    API latency; see results.md for that distinction."""
    started = time.monotonic()
    if simulate_latency:
        time.sleep(random.uniform(0.05, 0.15))

    owasp_category = _classify(finding)
    is_internet_facing = "internet-facing" in context.lower() or "public" in context.lower()
    priority = _prioritize(finding.severity, is_internet_facing)
    remediation = _REMEDIATION_TEMPLATES.get(finding.vuln_pattern, _GENERIC_REMEDIATION)
    if finding.file_path:
        remediation += f" (see {finding.file_path}:{finding.line_number})"

    explanation = _explain(finding, owasp_category)
    exploitability = _assess_exploitability(finding, is_internet_facing)
    business_impact = _assess_impact(finding, priority)

    result = TriageResult(
        finding_id=finding.id,
        owasp_category=owasp_category,
        explanation=explanation,
        exploitability=exploitability,
        business_impact=business_impact,
        remediation=remediation,
        priority=priority,
        is_internet_facing=is_internet_facing,
    )
    elapsed = time.monotonic() - started
    stats = {
        "wall_clock_seconds": elapsed,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
    }
    return result, stats


def _classify(finding: Finding) -> str:
    if finding.vuln_pattern and finding.vuln_pattern in _VULN_PATTERN_TO_OWASP:
        return _VULN_PATTERN_TO_OWASP[finding.vuln_pattern]

    desc_lower = finding.description.lower()
    for keywords, category in _KEYWORD_OWASP_HINTS:
        if any(kw in desc_lower for kw in keywords):
            return category

    return "Not Applicable / Infrastructure"


def _prioritize(severity: Severity, is_internet_facing: bool) -> Priority:
    base = {
        Severity.CRITICAL: Priority.CRITICAL,
        Severity.HIGH: Priority.HIGH,
        Severity.MEDIUM: Priority.MEDIUM,
        Severity.LOW: Priority.LOW,
        Severity.INFO: Priority.LOW,
        Severity.UNKNOWN: Priority.MEDIUM,
    }[severity]

    if is_internet_facing and base in (Priority.HIGH, Priority.MEDIUM):
        order = [Priority.CRITICAL, Priority.HIGH, Priority.MEDIUM, Priority.LOW]
        idx = max(0, order.index(base) - 1)
        return order[idx]
    return base


def _explain(finding: Finding, owasp_category: str) -> str:
    return (
        f"This is a {finding.severity.value.lower()}-severity {finding.vuln_pattern or 'finding'} "
        f"reported by {finding.source_tool.value}, mapped to {owasp_category}. {finding.description}"
    )


def _assess_exploitability(finding: Finding, is_internet_facing: bool) -> str:
    exposure = "internet-facing" if is_internet_facing else "not confirmed internet-facing"
    return (
        f"Asset is {exposure}. Raw evidence: {finding.raw_evidence[:200]}"
    )


def _assess_impact(finding: Finding, priority: Priority) -> str:
    if priority == Priority.CRITICAL:
        return "If exploited, this could lead to full compromise of the affected asset and any data or systems it can reach."
    if priority == Priority.HIGH:
        return "If exploited, this could lead to significant data exposure or service disruption for the affected asset."
    if priority == Priority.MEDIUM:
        return "If exploited, this could lead to limited data exposure or degraded functionality for the affected asset."
    return "Limited standalone impact, but may contribute to a larger attack chain if combined with other findings."
