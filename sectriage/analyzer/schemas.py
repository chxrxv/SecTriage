"""Structured-output schema and shared prompt text for the LLM triage step."""

OWASP_2021_CATEGORIES = [
    "A01:2021-Broken Access Control",
    "A02:2021-Cryptographic Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure Design",
    "A05:2021-Security Misconfiguration",
    "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures",
    "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures",
    "A10:2021-Server-Side Request Forgery (SSRF)",
    "Not Applicable / Infrastructure",
]

PRIORITY_LEVELS = ["Critical", "High", "Medium", "Low"]

TRIAGE_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "owasp_category": {
            "type": "string",
            "enum": OWASP_2021_CATEGORIES,
            "description": "The single best-fit OWASP Top 10 (2021) category for this finding.",
        },
        "explanation": {
            "type": "string",
            "description": "Plain-language explanation of what this vulnerability is and why it matters, for a reader who is not a security specialist.",
        },
        "exploitability": {
            "type": "string",
            "description": "Assessment of how exploitable this finding is given the provided context (internet-facing, auth required, complexity of attack).",
        },
        "business_impact": {
            "type": "string",
            "description": "Concrete business impact if exploited: what data or systems are at risk, and the realistic consequence.",
        },
        "remediation": {
            "type": "string",
            "description": "A concrete, actionable remediation step. If this is a source-code finding, include a code-level fix (e.g. the corrected line or snippet). If it is a scan finding, give a config-level fix.",
        },
        "priority": {
            "type": "string",
            "enum": PRIORITY_LEVELS,
            "description": "Overall priority combining severity, exploitability, and asset criticality.",
        },
        "is_internet_facing": {
            "type": "boolean",
            "description": "Whether the provided context indicates this asset is internet-facing.",
        },
    },
    "required": [
        "owasp_category",
        "explanation",
        "exploitability",
        "business_impact",
        "remediation",
        "priority",
        "is_internet_facing",
    ],
    "additionalProperties": False,
}

_CATEGORY_LINES = "\n".join(f"- {c}" for c in OWASP_2021_CATEGORIES[:-1])

SYSTEM_PROMPT = f"""You are a senior application security engineer performing triage on
findings produced by automated scanners (Nmap, OWASP ZAP) and a static source-code
scanner. For every finding you are given, you will:

1. Map it to the single best-fit OWASP Top 10 (2021) category:
{_CATEGORY_LINES}
   If the finding is purely infrastructure/network noise with no clean OWASP mapping
   (e.g. an open port with a benign service), use "Not Applicable / Infrastructure".

2. Explain the vulnerability in plain language: what it is, and why it matters. Assume
   the reader is a competent engineer who is not a security specialist — avoid jargon
   without a one-line definition, and be concrete rather than generic.

3. Assess exploitability using the context provided with the finding (is the asset
   internet-facing, does the endpoint require authentication, how complex is the
   attack path). A vulnerability on an internet-facing, unauthenticated endpoint is
   far more urgent than the identical bug on an internal, authenticated one.

4. Assess business impact concretely: name the data or system at risk and the
   realistic worst-case consequence (data breach, account takeover, service
   disruption, lateral movement, etc.) — not a generic "this could be bad."

5. Write ONE concrete, actionable remediation step:
   - For a source-code finding (file_path and line_number are set), give a
     code-level fix — show the corrected line(s), not just "use parameterized
     queries" in the abstract.
   - For a scan finding (Nmap/ZAP), give a config-level fix (close the port,
     disable the service, add a header, patch a version, etc.).

6. Assign a priority (Critical/High/Medium/Low) that combines the raw severity,
   your exploitability assessment, and asset criticality context. Two findings
   with identical raw severity can land at different priorities once
   exploitability and asset context are considered.

Judge each finding on its own evidence. Do not inflate severity for findings with
weak or purely theoretical evidence, and do not downplay a finding just because the
remediation looks simple.
"""


def build_user_prompt(finding_summary: str, evidence: str, context: str) -> str:
    return (
        f"FINDING:\n{finding_summary}\n\n"
        f"RAW EVIDENCE:\n{evidence}\n\n"
        f"CONTEXT:\n{context}\n\n"
        "Produce your triage now."
    )
