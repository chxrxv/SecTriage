"""Self-contained HTML report — inline CSS only, no external assets, so the
file works if emailed or opened directly from disk with no network access."""
from __future__ import annotations

import html
from datetime import datetime, timezone

from ..models import PRIORITY_ORDER, TriagedFinding

_PRIORITY_ORDER_LIST = ["Critical", "High", "Medium", "Low"]

_PRIORITY_COLORS = {
    "Critical": "#b91c1c",
    "High": "#c2410c",
    "Medium": "#a16207",
    "Low": "#15803d",
}

_CSS = """
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #5b5b5b; --card-bg: #f7f7f8;
  --border: #e0e0e0; --code-bg: #eef0f3;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #16171a; --fg: #e8e8e8; --muted: #a0a0a0; --card-bg: #1f2023; --border: #2e2f33; --code-bg: #22242a; }
}
* { box-sizing: border-box; }
body {
  background: var(--bg); color: var(--fg); margin: 0; padding: 2rem;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
.container { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin-bottom: 0.25rem; }
.subtitle { color: var(--muted); margin-bottom: 1.5rem; font-size: 0.9rem; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.summary-tile {
  border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem 1.25rem;
  background: var(--card-bg); min-width: 100px; text-align: center;
}
.summary-tile .count { font-size: 1.6rem; font-weight: 700; }
.summary-tile .label { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; }
h2.section-title {
  font-size: 1.15rem; margin-top: 2rem; padding-bottom: 0.4rem;
  border-bottom: 2px solid var(--border);
}
.card {
  border: 1px solid var(--border); border-left: 5px solid var(--priority-color, var(--border));
  border-radius: 8px; background: var(--card-bg); padding: 1rem 1.25rem; margin: 0.9rem 0;
}
.card-header { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; flex-wrap: wrap; }
.card-title { font-weight: 600; font-size: 1rem; }
.badge {
  display: inline-block; font-size: 0.72rem; font-weight: 700; padding: 0.15rem 0.5rem;
  border-radius: 4px; color: white; text-transform: uppercase; letter-spacing: 0.03em;
}
.meta { color: var(--muted); font-size: 0.82rem; margin: 0.3rem 0 0.7rem; }
.field { margin: 0.5rem 0; }
.field-label { font-weight: 600; font-size: 0.82rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.02em; }
.field-value { margin-top: 0.15rem; }
pre.evidence {
  background: var(--code-bg); border-radius: 6px; padding: 0.6rem 0.8rem; overflow-x: auto;
  font-size: 0.82rem; white-space: pre-wrap; word-break: break-word;
}
.dup-note { font-size: 0.8rem; color: var(--muted); font-style: italic; }
"""


def _card_html(tf: TriagedFinding) -> str:
    finding, triage = tf.finding, tf.triage
    color = _PRIORITY_COLORS.get(triage.priority.value, "#666")
    asset_line = html.escape(finding.affected_asset)
    if finding.file_path:
        asset_line += f" (line {finding.line_number})"

    return f"""
    <div class="card" style="--priority-color: {color}">
      <div class="card-header">
        <span class="card-title">{html.escape(finding.description)}</span>
        <span class="badge" style="background:{color}">{html.escape(triage.priority.value)}</span>
      </div>
      <div class="meta">
        {html.escape(triage.owasp_category)} &middot; source: {html.escape(finding.source_tool.value)}
        &middot; raw severity: {html.escape(finding.severity.value)}
        &middot; asset: {asset_line}
        {' &middot; internet-facing' if triage.is_internet_facing else ''}
      </div>
      <div class="field"><div class="field-label">What this is</div><div class="field-value">{html.escape(triage.explanation)}</div></div>
      <div class="field"><div class="field-label">Exploitability</div><div class="field-value">{html.escape(triage.exploitability)}</div></div>
      <div class="field"><div class="field-label">Business impact</div><div class="field-value">{html.escape(triage.business_impact)}</div></div>
      <div class="field"><div class="field-label">Remediation</div><div class="field-value">{html.escape(triage.remediation)}</div></div>
      <div class="field"><div class="field-label">Raw evidence</div><pre class="evidence">{html.escape(finding.raw_evidence)}</pre></div>
    </div>
    """


def render_html_report(triaged: list[TriagedFinding], metrics: dict) -> str:
    primary = [tf for tf in triaged if tf.triage.duplicate_of is None]
    duplicate_count = len(triaged) - len(primary)
    primary.sort(key=lambda tf: PRIORITY_ORDER[tf.triage.priority])

    counts = {p: 0 for p in _PRIORITY_ORDER_LIST}
    for tf in primary:
        counts[tf.triage.priority.value] += 1

    summary_tiles = "".join(
        f'<div class="summary-tile"><div class="count" style="color:{_PRIORITY_COLORS[p]}">{counts[p]}</div>'
        f'<div class="label">{p}</div></div>'
        for p in _PRIORITY_ORDER_LIST
    )

    sections = []
    for priority in _PRIORITY_ORDER_LIST:
        group = [tf for tf in primary if tf.triage.priority.value == priority]
        if not group:
            continue
        cards = "".join(_card_html(tf) for tf in group)
        sections.append(f'<h2 class="section-title">{priority} ({len(group)})</h2>{cards}')

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    dup_note = (
        f'<p class="dup-note">{duplicate_count} additional duplicate finding(s) from other tools were merged into the entries above.</p>'
        if duplicate_count
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecTriage Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <h1>SecTriage — Vulnerability Triage Report</h1>
  <div class="subtitle">Generated {generated_at} &middot; analyzer mode: {html.escape(metrics.get('mode', 'unknown'))}
  ({html.escape(str(metrics.get('model', '')))}) &middot; {len(triaged)} total findings, {len(primary)} unique</div>
  <div class="summary">{summary_tiles}</div>
  {dup_note}
  {"".join(sections)}
</div>
</body>
</html>
"""


def write_html_report(triaged: list[TriagedFinding], metrics: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html_report(triaged, metrics))
