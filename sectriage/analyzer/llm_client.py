"""Thin wrapper around the Anthropic Claude API for a single triage call.

Uses structured outputs (`output_config.format`) rather than prompt-and-parse —
the response is guaranteed to validate against TRIAGE_OUTPUT_SCHEMA. The system
prompt (OWASP category list + triage instructions) is identical for every
finding in a run, so it carries a `cache_control` breakpoint: after the first
call, subsequent calls reuse that cached prefix instead of re-processing it at
full price. Note the cacheable minimum is model-dependent (512 tokens on
Claude Opus 5 down to 4096 tokens on Haiku 4.5 — see shared/prompt-caching.md);
on a short system prompt with Haiku this may not actually engage, but the
breakpoint is harmless to leave in place and pays off as the prompt grows.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

from ..models import Finding, Priority, TriageResult
from .schemas import SYSTEM_PROMPT, TRIAGE_OUTPUT_SCHEMA, build_user_prompt

DEFAULT_LIVE_MODEL = "claude-haiku-4-5"


@dataclass
class LLMCallStats:
    wall_clock_seconds: float
    input_tokens: int
    output_tokens: int
    cache_read_input_tokens: int
    cache_creation_input_tokens: int


class LLMClient:
    """Lazily constructs the Anthropic client so mock mode never needs an API key."""

    def __init__(self, model: str = DEFAULT_LIVE_MODEL):
        self.model = model
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import anthropic  # imported lazily so mock mode has no hard dependency

            self._client = anthropic.Anthropic()
        return self._client

    def triage(self, finding: Finding, context: str) -> tuple[TriageResult, LLMCallStats]:
        finding_summary = f"[{finding.source_tool.value}] {finding.severity.value}: {finding.description}"
        if finding.file_path:
            finding_summary += f" ({finding.file_path}:{finding.line_number})"

        user_prompt = build_user_prompt(finding_summary, finding.raw_evidence, context)

        started = time.monotonic()
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            output_config={"format": {"type": "json_schema", "schema": TRIAGE_OUTPUT_SCHEMA}},
            messages=[{"role": "user", "content": user_prompt}],
        )
        elapsed = time.monotonic() - started

        text = next(block.text for block in response.content if block.type == "text")
        data = json.loads(text)

        result = TriageResult(
            finding_id=finding.id,
            owasp_category=data["owasp_category"],
            explanation=data["explanation"],
            exploitability=data["exploitability"],
            business_impact=data["business_impact"],
            remediation=data["remediation"],
            priority=Priority(data["priority"]),
            is_internet_facing=data["is_internet_facing"],
        )

        usage = response.usage
        stats = LLMCallStats(
            wall_clock_seconds=elapsed,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        )
        return result, stats
