"""Common data model shared by every parser, the analyzer, and the report renderers."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Raw severity as reported by the source tool (pre-LLM normalization)."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    UNKNOWN = "Unknown"


class SourceTool(str, Enum):
    NMAP = "nmap"
    ZAP = "zap"
    CODE_REVIEW = "code_review"


class Priority(str, Enum):
    """Final LLM-assigned priority, combining severity + exploitability + asset criticality."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


PRIORITY_ORDER = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3}


@dataclass
class Finding:
    """A single normalized vulnerability finding, before LLM triage."""

    source_tool: SourceTool
    severity: Severity
    description: str
    affected_asset: str
    raw_evidence: str
    id: str = ""
    file_path: str | None = None
    line_number: int | None = None
    vuln_pattern: str | None = None  # e.g. "sql_injection", "hardcoded_secret" (code findings only)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = self._compute_id()

    def _compute_id(self) -> str:
        key = f"{self.source_tool}:{self.affected_asset}:{self.description}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["source_tool"] = self.source_tool.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d["source_tool"] = SourceTool(d["source_tool"])
        d["severity"] = Severity(d["severity"])
        return cls(**d)


@dataclass
class TriageResult:
    """LLM-generated enrichment for a single Finding."""

    finding_id: str
    owasp_category: str
    explanation: str
    exploitability: str
    business_impact: str
    remediation: str
    priority: Priority
    is_internet_facing: bool = False
    duplicate_of: str | None = None  # set by dedup step; points at the finding_id it was merged into

    def to_dict(self) -> dict:
        d = asdict(self)
        d["priority"] = self.priority.value
        return d


@dataclass
class TriagedFinding:
    """A Finding paired with its TriageResult — the unit the report renderers operate on."""

    finding: Finding
    triage: TriageResult

    def to_dict(self) -> dict:
        return {"finding": self.finding.to_dict(), "triage": self.triage.to_dict()}
