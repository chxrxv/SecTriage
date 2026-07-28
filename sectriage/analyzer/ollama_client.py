"""Free, local, zero-payment triage backend via Ollama (https://ollama.com).

Runs entirely on the user's machine against a locally-downloaded open-source
model — no API key, no account, no billing, ever. Uses only the standard
library (urllib) so it doesn't pull in an extra HTTP dependency just for this
optional path. Mirrors LLMClient's `.triage()` interface so `triage.py` can
treat it as an interchangeable backend.

Tradeoffs vs. the Claude backend (documented, not hidden): small local models
are slower and meaningfully less reliable at following the OWASP taxonomy and
producing nuanced exploitability/business-impact reasoning. This exists so
the pipeline can be exercised end to end with real (non-mock) generated text
at zero cost — not as a substitute for the Claude-based results in results.md.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..models import Finding, Priority, TriageResult
from .schemas import SYSTEM_PROMPT, TRIAGE_OUTPUT_SCHEMA, build_user_prompt

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2:1b"


@dataclass
class OllamaCallStats:
    wall_clock_seconds: float
    prompt_tokens: int
    completion_tokens: int


class OllamaUnavailableError(RuntimeError):
    """Raised when the local Ollama server can't be reached or the model isn't pulled."""


def is_ollama_available(host: str = DEFAULT_OLLAMA_HOST, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(f"{host}/api/version", timeout=timeout):
            return True
    except (urllib.error.URLError, OSError):
        return False


class OllamaClient:
    def __init__(self, model: str = DEFAULT_OLLAMA_MODEL, host: str = DEFAULT_OLLAMA_HOST):
        self.model = model
        self.host = host

    def triage(self, finding: Finding, context: str) -> tuple[TriageResult, OllamaCallStats]:
        finding_summary = f"[{finding.source_tool.value}] {finding.severity.value}: {finding.description}"
        if finding.file_path:
            finding_summary += f" ({finding.file_path}:{finding.line_number})"

        user_prompt = build_user_prompt(finding_summary, finding.raw_evidence, context)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "format": TRIAGE_OUTPUT_SCHEMA,
            "stream": False,
            "options": {"temperature": 0},
        }

        started = time.monotonic()
        try:
            req = urllib.request.Request(
                f"{self.host}/api/chat",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError) as e:
            raise OllamaUnavailableError(
                f"Could not reach Ollama at {self.host} ({e}). "
                f"Is it running? Try `ollama serve`, and make sure `{self.model}` "
                f"has been pulled (`ollama pull {self.model}`)."
            ) from e
        elapsed = time.monotonic() - started

        content = body.get("message", {}).get("content", "")
        data = _parse_json_response(content)

        result = TriageResult(
            finding_id=finding.id,
            owasp_category=data["owasp_category"],
            explanation=data["explanation"],
            exploitability=data["exploitability"],
            business_impact=data["business_impact"],
            remediation=data["remediation"],
            priority=Priority(data["priority"]),
            is_internet_facing=bool(data["is_internet_facing"]),
        )
        stats = OllamaCallStats(
            wall_clock_seconds=elapsed,
            prompt_tokens=body.get("prompt_eval_count", 0) or 0,
            completion_tokens=body.get("eval_count", 0) or 0,
        )
        return result, stats


def _parse_json_response(content: str) -> dict:
    """Small local models occasionally wrap the JSON in prose or code fences
    despite the schema constraint, so fall back to extracting the first
    top-level {...} block before giving up."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Ollama response was not valid JSON and no JSON object could be extracted: {content[:300]!r}")
