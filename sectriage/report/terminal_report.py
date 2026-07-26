"""Plain-text terminal summary table - no third-party dependency (no `rich`/`tabulate`)
so the CLI has zero extra install cost beyond the `anthropic` SDK.

ASCII-only by design: Windows consoles commonly default to a codepage (e.g.
cp1252) that mangles em-dashes and ellipses into '?' / mojibake, so this
module avoids non-ASCII characters entirely rather than requiring the caller
to fix their terminal encoding."""
from __future__ import annotations

from ..models import PRIORITY_ORDER, TriagedFinding

_PRIORITY_ORDER_LIST = ["Critical", "High", "Medium", "Low"]


def _truncate(s: str, width: int) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= width else s[: width - 3] + "..."


def render_terminal_summary(triaged: list[TriagedFinding]) -> str:
    primary = [tf for tf in triaged if tf.triage.duplicate_of is None]
    duplicate_count = len(triaged) - len(primary)

    primary.sort(key=lambda tf: PRIORITY_ORDER[tf.triage.priority])

    counts = {p: 0 for p in _PRIORITY_ORDER_LIST}
    for tf in primary:
        counts[tf.triage.priority.value] += 1

    lines: list[str] = []
    lines.append("=" * 100)
    lines.append("SecTriage - Vulnerability Triage Summary")
    lines.append("=" * 100)
    summary_bits = [f"{p}: {counts[p]}" for p in _PRIORITY_ORDER_LIST]
    lines.append(
        f"Total findings: {len(triaged)}  |  Unique after dedup: {len(primary)}"
        f"  ({duplicate_count} duplicate{'s' if duplicate_count != 1 else ''} merged)"
    )
    lines.append("  ".join(summary_bits))
    lines.append("-" * 100)

    header = f"{'PRIORITY':<9} {'OWASP CATEGORY':<38} {'ASSET':<28} {'DESCRIPTION':<40}"
    lines.append(header)
    lines.append("-" * 100)

    for tf in primary:
        row = (
            f"{tf.triage.priority.value:<9} "
            f"{_truncate(tf.triage.owasp_category, 37):<38} "
            f"{_truncate(tf.finding.affected_asset, 27):<28} "
            f"{_truncate(tf.finding.description, 39):<40}"
        )
        lines.append(row)

    lines.append("=" * 100)
    return "\n".join(lines)
