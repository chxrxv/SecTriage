"""Cross-tool deduplication.

Findings from different tools can point at the same root cause — e.g. Nmap
flagging an outdated TLS service on port 443 and ZAP flagging a weak-cipher
alert against https://host/ (also port 443). This module merges two findings
only when BOTH of the following hold:

1. They come from **different source tools**. Two findings from the same tool
   are never candidates for merging here — the tool already reported them as
   distinct, and (critically) two genuinely different findings from one tool
   often share a broad OWASP bucket without being duplicates at all (e.g. a
   ZAP SQL-injection alert on /search and a ZAP XSS alert on /greet both map
   to A03:2021-Injection, but they are not the same finding). An earlier
   version of this module grouped by asset+category without the same-tool
   guard and silently collapsed unrelated findings that shared a category —
   see git history / tests/test_dedup.py for the regression test.
2. They resolve to the same **host:port** (not just host) and the same OWASP
   category. Nmap's `"host (hostname):port/proto"` format and ZAP's full URLs
   are both parsed down to `host:port` (URLs get a default port from their
   scheme) so "port 22" and "port 443" on the same host never collide, but a
   ZAP alert on port 80 and an Nmap finding also on port 80 will.

This is still a heuristic, not semantic dedup — it can miss a genuine
same-root-cause pair whose OWASP mapping differs between tools, and it has no
way to compare findings more precisely than host:port + category (e.g. it
cannot tell that two *different*-category alerts on the same port really are
about the same misconfiguration). Both are accepted limitations for a
lightweight heuristic.

Source-code findings (`"file.py:39"`) fall out of this naturally: they parse
to a `file.py:39` key that's already unique per line, and the different-tool
guard means two code-review findings never merge with each other regardless.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import PRIORITY_ORDER, TriagedFinding

# Nmap's asset format: "<ip>[ (<hostname>)]:<port>/<tcp|udp>"
_NMAP_ASSET_RE = re.compile(r"^([^\s(:]+)(?:\s*\(([^)]*)\))?:(\d+)/(?:tcp|udp)$", re.IGNORECASE)
# Generic "<host>:<port>" with nothing else trailing (covers plain host:port,
# and incidentally "file.py:39", which is fine — see module docstring).
_HOST_PORT_RE = re.compile(r"^([^:\s]+):(\d+)$")

_DEFAULT_PORT_BY_SCHEME = {"http": 80, "https": 443, "ftp": 21}


def _normalize_asset(asset: str) -> str:
    """Best-effort extraction of a `host:port` (or bare `host`) identity from
    an Nmap asset string, a ZAP URL, or anything else. Falls back to the
    lowercased input unchanged if none of the known shapes match."""
    if "://" in asset:
        parsed = urlparse(asset)
        host = (parsed.hostname or "").lower()
        port = parsed.port or _DEFAULT_PORT_BY_SCHEME.get(parsed.scheme, None)
        return f"{host}:{port}" if port else host

    m = _NMAP_ASSET_RE.match(asset)
    if m:
        ip, hostname, port = m.group(1), m.group(2), m.group(3)
        # Prefer the resolved hostname over the bare IP when Nmap reported
        # one: ZAP almost always identifies assets by hostname (it's crawling
        # URLs), so keying on the IP would make a real same-host match between
        # the two tools nearly impossible in practice.
        host = (hostname or ip).lower()
        return f"{host}:{port}"

    m = _HOST_PORT_RE.match(asset)
    if m:
        return f"{m.group(1).lower()}:{m.group(2)}"

    return asset.lower()


def deduplicate(triaged: list[TriagedFinding]) -> list[TriagedFinding]:
    """Returns the same findings, with `triage.duplicate_of` set on every finding
    that was grouped under a higher-priority finding sharing the same normalized
    host:port and OWASP category, AND reported by a different tool. Callers
    that want a collapsed view should filter out entries where `duplicate_of
    is not None`; nothing is deleted."""
    groups: dict[tuple[str, str], list[TriagedFinding]] = {}

    for tf in triaged:
        key = (_normalize_asset(tf.finding.affected_asset), tf.triage.owasp_category)
        groups.setdefault(key, []).append(tf)

    for group in groups.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda tf: PRIORITY_ORDER[tf.triage.priority])

        # The highest-priority finding (after the sort) anchors the group.
        # Only findings from a *different* tool than the anchor are merged
        # into it — same-tool findings sharing this asset+category are left
        # independent (see module docstring point 1).
        anchor = group[0]
        for tf in group[1:]:
            if tf.finding.source_tool != anchor.finding.source_tool:
                tf.triage.duplicate_of = anchor.finding.id

    return triaged
