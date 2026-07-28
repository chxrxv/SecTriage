"""Orchestrates per-finding triage calls (mock, Claude, or local Ollama) and
aggregates run metrics."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Finding, TriagedFinding
from .llm_client import DEFAULT_LIVE_MODEL, LLMClient
from .mock import mock_triage
from .ollama_client import DEFAULT_OLLAMA_HOST, DEFAULT_OLLAMA_MODEL, OllamaClient

PROVIDERS = ("claude", "ollama")


@dataclass
class TriageMetrics:
    mode: str
    model: str
    total_findings: int = 0
    total_wall_clock_seconds: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cache_read_tokens: int = 0
    total_cache_creation_tokens: int = 0
    per_finding_seconds: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "model": self.model,
            "total_findings": self.total_findings,
            "total_wall_clock_seconds": round(self.total_wall_clock_seconds, 3),
            "avg_seconds_per_finding": round(
                self.total_wall_clock_seconds / self.total_findings, 3
            )
            if self.total_findings
            else 0,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cache_read_tokens": self.total_cache_read_tokens,
            "total_cache_creation_tokens": self.total_cache_creation_tokens,
        }


def _build_context(finding: Finding, internet_facing: bool) -> str:
    parts = []
    parts.append("internet-facing" if internet_facing else "internal/unspecified network exposure")
    if finding.file_path:
        parts.append(f"source-code finding in {finding.file_path}")
    else:
        parts.append(f"asset identifier: {finding.affected_asset}")
    return "; ".join(parts)


def _default_model_for(provider: str) -> str:
    return DEFAULT_OLLAMA_MODEL if provider == "ollama" else DEFAULT_LIVE_MODEL


def triage_findings(
    findings: list[Finding],
    live: bool = False,
    provider: str = "claude",
    model: str | None = None,
    internet_facing: bool = False,
    ollama_host: str = DEFAULT_OLLAMA_HOST,
) -> tuple[list[TriagedFinding], TriageMetrics]:
    """`live=False` always uses the free mock analyzer regardless of `provider`.
    `live=True` dispatches to `provider` ("claude" — paid, requires
    ANTHROPIC_API_KEY — or "ollama" — free, requires a local Ollama server)."""
    if live and provider not in PROVIDERS:
        raise ValueError(f"Unknown provider {provider!r}; expected one of {PROVIDERS}")

    resolved_model = model or _default_model_for(provider)
    metrics = TriageMetrics(
        mode=f"live:{provider}" if live else "mock",
        model=resolved_model if live else "mock-analyzer",
    )

    client = None
    if live:
        client = (
            OllamaClient(model=resolved_model, host=ollama_host)
            if provider == "ollama"
            else LLMClient(model=resolved_model)
        )

    results: list[TriagedFinding] = []
    for finding in findings:
        context = _build_context(finding, internet_facing)

        if live:
            triage_result, stats = client.triage(finding, context)
            wall_clock = stats.wall_clock_seconds
            if provider == "claude":
                metrics.total_input_tokens += stats.input_tokens
                metrics.total_output_tokens += stats.output_tokens
                metrics.total_cache_read_tokens += stats.cache_read_input_tokens
                metrics.total_cache_creation_tokens += stats.cache_creation_input_tokens
            else:  # ollama
                metrics.total_input_tokens += stats.prompt_tokens
                metrics.total_output_tokens += stats.completion_tokens
        else:
            triage_result, stats = mock_triage(finding, context)
            wall_clock = stats["wall_clock_seconds"]

        metrics.total_wall_clock_seconds += wall_clock
        metrics.per_finding_seconds.append(wall_clock)
        metrics.total_findings += 1

        results.append(TriagedFinding(finding=finding, triage=triage_result))

    return results, metrics
