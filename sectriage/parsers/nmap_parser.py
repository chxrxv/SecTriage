"""Parser for Nmap output — XML (`nmap -oX`) preferred, with a fallback for plain
`-oN`/greppable text output."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..models import Finding, Severity, SourceTool

# Services that are inherently risky when exposed, independent of any script output.
_RISKY_SERVICES = {
    "telnet": Severity.HIGH,
    "ftp": Severity.MEDIUM,
    "rlogin": Severity.HIGH,
    "rsh": Severity.HIGH,
    "vnc": Severity.HIGH,
    "rdp": Severity.MEDIUM,
    "ms-wbt-server": Severity.MEDIUM,
    "smb": Severity.MEDIUM,
    "microsoft-ds": Severity.MEDIUM,
    "netbios-ssn": Severity.MEDIUM,
    "mysql": Severity.MEDIUM,
    "postgresql": Severity.MEDIUM,
    "mongodb": Severity.MEDIUM,
    "redis": Severity.MEDIUM,
    "snmp": Severity.MEDIUM,
}

_GREP_LINE_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)\s*(?P<version>.*)$"
)


def parse_nmap(path: str) -> list[Finding]:
    """Parse an Nmap scan file. Tries XML first, falls back to plain-text line scanning."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    stripped = content.lstrip()
    if stripped.startswith("<?xml") or stripped.startswith("<nmaprun"):
        return _parse_nmap_xml(content)
    return _parse_nmap_text(content)


def _parse_nmap_xml(content: str) -> list[Finding]:
    findings: list[Finding] = []
    root = ET.fromstring(content)

    for host in root.findall("host"):
        addr_el = host.find("address")
        host_addr = addr_el.get("addr") if addr_el is not None else "unknown-host"

        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        asset_label = f"{host_addr}" + (f" ({hostname})" if hostname else "")

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = port.get("portid", "?")
            proto = port.get("protocol", "tcp")
            service_el = port.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            version_str = " ".join(p for p in (product, version) if p)

            asset = f"{asset_label}:{portid}/{proto}"
            base_severity = _RISKY_SERVICES.get(service_name.lower(), Severity.LOW)
            description = f"Open port {portid}/{proto} running {service_name}"
            if version_str:
                description += f" ({version_str})"

            evidence_lines = [f"port={portid}/{proto} state=open service={service_name} {version_str}".strip()]

            # Script output attached to this specific port (e.g. vulners, ssl-*, http-*)
            severity = base_severity
            for script in port.findall("script"):
                script_id = script.get("id", "")
                output = script.get("output", "")
                evidence_lines.append(f"script[{script_id}]: {output.strip()[:500]}")
                if _looks_vulnerable(output):
                    severity = Severity.CRITICAL if "CVE-" in output else Severity.HIGH

            findings.append(
                Finding(
                    source_tool=SourceTool.NMAP,
                    severity=severity,
                    description=description,
                    affected_asset=asset,
                    raw_evidence="\n".join(evidence_lines),
                )
            )

        # Host-level scripts (not tied to a specific port), e.g. OS/vuln scripts
        hostscript_el = host.find("hostscript")
        if hostscript_el is not None:
            for script in hostscript_el.findall("script"):
                script_id = script.get("id", "")
                output = script.get("output", "")
                if _looks_vulnerable(output):
                    severity = Severity.CRITICAL if "CVE-" in output else Severity.HIGH
                    findings.append(
                        Finding(
                            source_tool=SourceTool.NMAP,
                            severity=severity,
                            description=f"Host script '{script_id}' reported a vulnerability",
                            affected_asset=asset_label,
                            raw_evidence=output.strip()[:1000],
                        )
                    )

    return findings


def _parse_nmap_text(content: str) -> list[Finding]:
    findings: list[Finding] = []
    current_host = "unknown-host"

    for line in content.splitlines():
        line = line.strip()
        host_match = re.match(r"^Nmap scan report for (.+)$", line)
        if host_match:
            current_host = host_match.group(1).strip()
            continue

        m = _GREP_LINE_RE.match(line)
        if not m:
            continue

        port = m.group("port")
        proto = m.group("proto")
        service = m.group("service")
        version = m.group("version").strip()

        asset = f"{current_host}:{port}/{proto}"
        severity = _RISKY_SERVICES.get(service.lower(), Severity.LOW)
        description = f"Open port {port}/{proto} running {service}"
        if version:
            description += f" ({version})"

        findings.append(
            Finding(
                source_tool=SourceTool.NMAP,
                severity=severity,
                description=description,
                affected_asset=asset,
                raw_evidence=line,
            )
        )

    return findings


def _looks_vulnerable(script_output: str) -> bool:
    if not script_output:
        return False
    markers = ("VULNERABLE", "CVE-", "EXPLOIT")
    upper = script_output.upper()
    return any(marker in upper for marker in markers)
