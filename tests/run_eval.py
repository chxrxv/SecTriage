#!/usr/bin/env python
"""Accuracy + timing evaluation harness.

Run with:
    python tests/run_eval.py                 # mock analyzer, $0 cost
    python tests/run_eval.py --live           # real Claude API (needs ANTHROPIC_API_KEY)

Writes results.md at the project root. Two things are measured:

1. Static code scanner detection accuracy — precision/recall/F1 against the
   hand-authored ground_truth.json manifest for tests/fixtures/vulnerable_app.
   This is the part with a real, checkable answer key.

2. End-to-end pipeline throughput across all three input types (Nmap + ZAP +
   code) versus an assumed manual-review baseline. The manual-review time is
   an explicitly-stated assumption (not something we measured against a human
   reviewer), so the "time saved" figure is clearly labeled as such rather than
   presented as an observed fact.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sectriage.analyzer import triage_findings  # noqa: E402
from sectriage.parsers import parse_nmap, parse_zap, scan_codebase  # noqa: E402
from sectriage.report import deduplicate  # noqa: E402

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
VULN_APP_DIR = os.path.join(FIXTURES_DIR, "vulnerable_app")
GROUND_TRUTH_PATH = os.path.join(VULN_APP_DIR, "ground_truth.json")
NMAP_FIXTURE = os.path.join(FIXTURES_DIR, "nmap_sample.xml")
ZAP_FIXTURE = os.path.join(FIXTURES_DIR, "zap_sample.json")
RESULTS_MD_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results.md")

# Explicitly-stated assumption, not a measured value — see results.md methodology
# section. This is a commonly-cited rule of thumb for the time a security
# engineer spends per finding to triage manually: re-locate the code/asset,
# determine the correct OWASP category, judge exploitability and business
# impact from context, and write a concrete remediation step.
ASSUMED_MANUAL_MINUTES_PER_FINDING = 15


def _line_distance_ok(a: int, b: int, tolerance: int = 2) -> bool:
    return abs(a - b) <= tolerance


def evaluate_code_scanner_accuracy() -> dict:
    with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)["entries"]

    started = time.monotonic()
    findings = scan_codebase(VULN_APP_DIR)
    scan_seconds = time.monotonic() - started

    # Normalize scanner file paths (posix-style, relative) for comparison
    scanner_by_file: dict[str, list] = {}
    for f in findings:
        key = (f.file_path or "").replace("\\", "/")
        scanner_by_file.setdefault(key, []).append(f)

    tp = fp = fn = tn = 0
    matched_scanner_ids = set()
    details = []

    for entry in ground_truth:
        file_key = entry["file"]
        candidates = [
            c
            for c in scanner_by_file.get(file_key, [])
            if c.id not in matched_scanner_ids
            and c.vuln_pattern == entry["vuln_pattern"]
            and _line_distance_ok(c.line_number, entry["line"])
        ]
        # Nearest line wins — matters when two ground-truth entries for the
        # same vuln_pattern sit within `tolerance` lines of each other (e.g.
        # lines 25/26 here), so each scanner finding is claimed by at most one
        # ground-truth entry instead of the first entry grabbing both.
        candidates.sort(key=lambda c: abs(c.line_number - entry["line"]))
        match = candidates[0] if candidates else None
        found = match is not None
        if match is not None:
            matched_scanner_ids.add(match.id)

        vulnerable = entry["is_actually_vulnerable"]
        if vulnerable and found:
            tp += 1
            outcome = "TP"
        elif vulnerable and not found:
            fn += 1
            outcome = "FN"
        elif not vulnerable and found:
            fp += 1
            outcome = "FP"
        else:
            tn += 1
            outcome = "TN"

        details.append(
            {
                "file": file_key,
                "line": entry["line"],
                "vuln_pattern": entry["vuln_pattern"],
                "outcome": outcome,
                "note": entry.get("note", ""),
            }
        )

    # Findings the scanner produced in fixture files that don't correspond to
    # ANY ground-truth entry at all (not even a false-positive-expected one) —
    # these would indicate the manifest is out of date, not a real defect, so
    # they're reported separately for manifest-maintenance purposes.
    unaccounted = [f for f in findings if f.id not in matched_scanner_ids]

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "scan_seconds": scan_seconds,
        "total_findings_in_fixture": len(findings),
        "ground_truth_entries": len(ground_truth),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "details": details,
        "unaccounted_findings": [
            {"file": f.file_path, "line": f.line_number, "vuln_pattern": f.vuln_pattern} for f in unaccounted
        ],
    }


def evaluate_pipeline_throughput(live: bool) -> dict:
    all_findings = []
    all_findings.extend(parse_nmap(NMAP_FIXTURE))
    all_findings.extend(parse_zap(ZAP_FIXTURE))
    all_findings.extend(scan_codebase(VULN_APP_DIR))

    started = time.monotonic()
    triaged, metrics = triage_findings(all_findings, live=live)
    triaged = deduplicate(triaged)
    pipeline_seconds = time.monotonic() - started

    unique_count = len([tf for tf in triaged if tf.triage.duplicate_of is None])
    manual_minutes = len(all_findings) * ASSUMED_MANUAL_MINUTES_PER_FINDING
    manual_seconds = manual_minutes * 60
    # Mock-mode wall-clock is pipeline plumbing overhead, not real LLM latency —
    # a "% time reduction" computed from it would be a meaningless near-100%
    # artifact of comparing ~3s of local code to a 7.5-hour manual baseline.
    # Only report this figure for --live runs, where the wall-clock is real.
    pct_reduction = (1 - (pipeline_seconds / manual_seconds)) * 100 if (live and manual_seconds) else None

    return {
        "total_findings": len(all_findings),
        "unique_findings_after_dedup": unique_count,
        "duplicates_merged": len(all_findings) - unique_count,
        "pipeline_seconds": pipeline_seconds,
        "assumed_manual_minutes_per_finding": ASSUMED_MANUAL_MINUTES_PER_FINDING,
        "assumed_manual_total_minutes": manual_minutes,
        "pct_time_reduction_vs_assumed_manual": pct_reduction,
        "metrics": metrics.to_dict(),
    }


def render_results_md(accuracy: dict, throughput: dict, live: bool) -> str:
    mode_label = "LIVE (real Claude API)" if live else "MOCK (deterministic, $0 cost)"
    lines = []
    lines.append("# SecTriage — Accuracy & Performance Results\n")
    lines.append(
        f"Generated by `tests/run_eval.py` in **{mode_label}** mode. "
        "Re-run with `python tests/run_eval.py --live` (requires `ANTHROPIC_API_KEY`) "
        "to reproduce these numbers against the real LLM analyzer.\n"
    )

    lines.append("## 1. Static code scanner detection accuracy\n")
    lines.append(
        "Measured against `tests/fixtures/vulnerable_app/ground_truth.json`, a hand-authored "
        f"manifest of {accuracy['ground_truth_entries']} labeled lines (true vulnerabilities, "
        "true-negative safe code, one deliberately-injected multi-line vulnerability the scanner "
        "is expected to miss, and one deliberate false-positive case documenting a known "
        "data-flow-analysis limitation).\n"
    )
    lines.append(f"- **Precision: {accuracy['precision']:.1%}** ({accuracy['tp']} TP / {accuracy['tp'] + accuracy['fp']} flagged)")
    lines.append(f"- **Recall: {accuracy['recall']:.1%}** ({accuracy['tp']} TP / {accuracy['tp'] + accuracy['fn']} actually vulnerable)")
    lines.append(f"- **F1: {accuracy['f1']:.2f}**")
    lines.append(
        f"- Confusion matrix: TP={accuracy['tp']}, FP={accuracy['fp']}, FN={accuracy['fn']}, TN={accuracy['tn']}"
    )
    lines.append(f"- Codebase scan wall-clock: {accuracy['scan_seconds']:.3f}s\n")

    if accuracy["unaccounted_findings"]:
        lines.append(
            f"⚠️ {len(accuracy['unaccounted_findings'])} scanner finding(s) in the fixture did not "
            "match any ground-truth entry (manifest may be stale):\n"
        )
        for uf in accuracy["unaccounted_findings"]:
            lines.append(f"  - {uf['file']}:{uf['line']} ({uf['vuln_pattern']})")
        lines.append("")

    lines.append("### Per-finding breakdown\n")
    lines.append("| File | Line | Pattern | Outcome | Note |")
    lines.append("|---|---|---|---|---|")
    for d in accuracy["details"]:
        lines.append(f"| {d['file']} | {d['line']} | {d['vuln_pattern']} | **{d['outcome']}** | {d['note']} |")
    lines.append("")

    lines.append("## 2. End-to-end pipeline throughput vs. assumed manual baseline\n")
    lines.append(
        f"Full pipeline (Nmap + ZAP + code review → LLM triage → dedup) run against all "
        f"three sample fixtures: **{throughput['total_findings']} findings** parsed, "
        f"**{throughput['unique_findings_after_dedup']} unique** after cross-tool dedup "
        f"({throughput['duplicates_merged']} merged).\n"
    )
    lines.append(f"- Pipeline wall-clock: **{throughput['pipeline_seconds']:.2f}s** "
                  f"({throughput['metrics']['avg_seconds_per_finding']:.3f}s/finding avg, {mode_label.split(' ')[0].lower()} analyzer)")
    lines.append(
        f"- Assumed manual review baseline: **{throughput['assumed_manual_minutes_per_finding']} min/finding** "
        f"(industry rule-of-thumb for locating, classifying, and writing up one finding by hand — "
        "*not independently measured in this project*; treat as a directional assumption, not a "
        f"controlled study) → {throughput['assumed_manual_total_minutes']} minutes total for "
        f"{throughput['total_findings']} findings."
    )

    if throughput["pct_time_reduction_vs_assumed_manual"] is not None:
        lines.append(
            f"- **Implied time reduction: {throughput['pct_time_reduction_vs_assumed_manual']:.1f}%** "
            "versus the assumed manual baseline above.\n"
        )
    else:
        lines.append(
            "- Time-reduction percentage: **not computed in mock mode** — see cost note below. "
            "A mock-mode wall-clock is local-code overhead, not model latency, so dividing it into "
            "the manual baseline would produce a meaningless near-100% number rather than a real "
            "measurement.\n"
        )

    if not live:
        lines.append(
            "> **Cost note:** this run used the free mock analyzer (no API calls, no tokens). "
            "It measures pipeline plumbing overhead (parsing, dedup, report rendering), NOT real "
            "LLM latency or cost. Run `python tests/run_eval.py --live` with a Claude API key to "
            "get real per-finding latency, token usage, prompt-cache hit rate, and a genuine "
            f"time-reduction figure for the `{throughput['metrics']['model']}` analyzer.\n"
        )
    else:
        lines.append(
            f"- Model: `{throughput['metrics']['model']}` &middot; "
            f"input tokens: {throughput['metrics']['total_input_tokens']} &middot; "
            f"output tokens: {throughput['metrics']['total_output_tokens']} &middot; "
            f"cache read tokens: {throughput['metrics']['total_cache_read_tokens']} &middot; "
            f"cache write tokens: {throughput['metrics']['total_cache_creation_tokens']}\n"
        )

    lines.append("## Methodology notes and honest caveats\n")
    lines.append(
        "- The fixture app (`tests/fixtures/vulnerable_app`) was written *for this project*, with "
        "the ground-truth manifest derived from inline marker comments in the source — it is not "
        "an independent, blind test set, and the scanner's regex rules were developed alongside it. "
        "Treat the accuracy numbers above as a controlled unit-test result, not a claim about "
        "real-world codebases."
    )
    lines.append(
        "- The manual-review-time baseline (15 min/finding) is a stated assumption, not something "
        "measured against a human reviewer in this project. It is a plausible order-of-magnitude "
        "figure for security triage work, not a citation-backed number."
    )
    lines.append(
        "- Mock-mode timing measures pipeline overhead only; it is not representative of real LLM "
        "API latency. Live-mode numbers (see above) are the ones that reflect actual model latency, "
        "token cost, and prompt-cache behavior."
    )
    lines.append(
        "- The static scanner is line-based pattern matching, not full data-flow/taint analysis — "
        "see the FN and FP rows in the breakdown table above for concrete, deliberately-included "
        "examples of both failure modes."
    )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Use the real Claude API instead of the mock analyzer")
    args = parser.parse_args()

    if args.live and not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: --live requires ANTHROPIC_API_KEY to be set", file=sys.stderr)
        return 1

    print("Evaluating static code scanner accuracy against ground_truth.json...")
    accuracy = evaluate_code_scanner_accuracy()
    print(f"  precision={accuracy['precision']:.1%} recall={accuracy['recall']:.1%} f1={accuracy['f1']:.2f}")

    print(f"Evaluating end-to-end pipeline throughput ({'live' if args.live else 'mock'} analyzer)...")
    throughput = evaluate_pipeline_throughput(live=args.live)
    print(f"  {throughput['total_findings']} findings, {throughput['pipeline_seconds']:.2f}s wall-clock")

    results_md = render_results_md(accuracy, throughput, live=args.live)
    with open(RESULTS_MD_PATH, "w", encoding="utf-8") as f:
        f.write(results_md)
    print(f"\nWrote {RESULTS_MD_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
