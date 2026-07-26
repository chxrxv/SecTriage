"""Parser for OWASP ZAP JSON reports (the JSON export of a ZAP scan report, or
`zap-cli report -f json` output). Structure: {"site": [{"alerts": [...]}]}."""
from __future__ import annotations

import json

from ..models import Finding, Severity, SourceTool

_RISKCODE_TO_SEVERITY = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

_RISKDESC_TO_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


def parse_zap(path: str) -> list[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    findings: list[Finding] = []
    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_host = site.get("@name") or site.get("@host") or "unknown-site"
        alerts = site.get("alerts", [])

        for alert in alerts:
            severity = _resolve_severity(alert)
            name = alert.get("alert") or alert.get("name") or "Unnamed ZAP alert"
            desc = (alert.get("desc") or "").strip()
            solution = (alert.get("solution") or "").strip()
            cwe = alert.get("cweid", "")

            instances = alert.get("instances", [])
            if isinstance(instances, dict):
                instances = [instances]

            uris = [inst.get("uri", "") for inst in instances if inst.get("uri")]
            asset = uris[0] if uris else site_host

            evidence_parts = [f"ZAP plugin {alert.get('pluginid', '?')} — {name} (CWE-{cwe})" if cwe else f"ZAP plugin {alert.get('pluginid', '?')} — {name}"]
            if desc:
                evidence_parts.append(f"Description: {desc[:800]}")
            if solution:
                evidence_parts.append(f"ZAP-suggested solution: {solution[:500]}")
            for inst in instances[:5]:
                line = f"  instance: {inst.get('method', 'GET')} {inst.get('uri', '')}"
                if inst.get("param"):
                    line += f" param={inst['param']}"
                if inst.get("evidence"):
                    line += f" evidence={inst['evidence'][:200]!r}"
                evidence_parts.append(line)
            if len(instances) > 5:
                evidence_parts.append(f"  ... and {len(instances) - 5} more instances")

            affected_count = len(instances) if instances else 1
            description = f"{name} ({affected_count} instance{'s' if affected_count != 1 else ''})"

            findings.append(
                Finding(
                    source_tool=SourceTool.ZAP,
                    severity=severity,
                    description=description,
                    affected_asset=asset,
                    raw_evidence="\n".join(evidence_parts),
                )
            )

    return findings


def _resolve_severity(alert: dict) -> Severity:
    riskcode = str(alert.get("riskcode", "")).strip()
    if riskcode in _RISKCODE_TO_SEVERITY:
        return _RISKCODE_TO_SEVERITY[riskcode]

    riskdesc = str(alert.get("riskdesc", "")).strip().lower()
    for key, sev in _RISKDESC_TO_SEVERITY.items():
        if riskdesc.startswith(key):
            return sev

    return Severity.UNKNOWN
