"""CLI entry point.

    sectriage scan --nmap results.xml --zap zap-report.json --code ./repo
    sectriage scan --code ./repo --live --internet-facing
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from .analyzer import triage_findings
from .analyzer.llm_client import DEFAULT_LIVE_MODEL
from .models import Finding
from .parsers import parse_nmap, parse_zap, scan_codebase
from .report import deduplicate, render_terminal_summary
from .report.html_report import write_html_report
from .report.json_report import write_json_report


def _collect_findings(args: argparse.Namespace) -> list[Finding]:
    findings: list[Finding] = []

    if args.nmap:
        if not os.path.isfile(args.nmap):
            print(f"error: --nmap file not found: {args.nmap}", file=sys.stderr)
            sys.exit(1)
        nmap_findings = parse_nmap(args.nmap)
        print(f"Parsed {len(nmap_findings)} finding(s) from Nmap: {args.nmap}")
        findings.extend(nmap_findings)

    if args.zap:
        if not os.path.isfile(args.zap):
            print(f"error: --zap file not found: {args.zap}", file=sys.stderr)
            sys.exit(1)
        zap_findings = parse_zap(args.zap)
        print(f"Parsed {len(zap_findings)} finding(s) from ZAP: {args.zap}")
        findings.extend(zap_findings)

    if args.code:
        if not os.path.isdir(args.code):
            print(f"error: --code path is not a directory: {args.code}", file=sys.stderr)
            sys.exit(1)
        code_findings = scan_codebase(args.code)
        print(f"Found {len(code_findings)} finding(s) from static code review: {args.code}")
        findings.extend(code_findings)

    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    if not (args.nmap or args.zap or args.code):
        print("error: provide at least one of --nmap, --zap, --code", file=sys.stderr)
        return 1

    if args.live and not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "error: --live requires ANTHROPIC_API_KEY to be set in the environment.\n"
            "       Omit --live to run the free mock analyzer instead.",
            file=sys.stderr,
        )
        return 1

    findings = _collect_findings(args)
    if not findings:
        print("No findings to triage.")
        return 0

    mode = "live" if args.live else "mock"
    print(f"\nTriaging {len(findings)} finding(s) with the {mode} analyzer"
          f"{f' ({args.model})' if args.live else ''}...")

    started = time.monotonic()
    triaged, metrics = triage_findings(
        findings, live=args.live, model=args.model, internet_facing=args.internet_facing
    )
    triaged = deduplicate(triaged)
    total_elapsed = time.monotonic() - started

    print(render_terminal_summary(triaged))
    print(
        f"\nTriage wall-clock: {total_elapsed:.2f}s "
        f"({metrics.to_dict()['avg_seconds_per_finding']:.3f}s/finding avg)"
    )

    os.makedirs(args.out_dir, exist_ok=True)
    json_path = os.path.join(args.out_dir, "report.json")
    html_path = os.path.join(args.out_dir, "report.html")
    write_json_report(triaged, metrics.to_dict(), json_path)
    write_html_report(triaged, metrics.to_dict(), html_path)

    print(f"\nJSON report: {json_path}")
    print(f"HTML report: {html_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sectriage", description="LLM-powered security vulnerability triage agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Parse scan outputs / review code and produce a triaged report")
    scan_parser.add_argument("--nmap", help="Path to Nmap XML or text output")
    scan_parser.add_argument("--zap", help="Path to OWASP ZAP JSON report")
    scan_parser.add_argument("--code", help="Path to a local codebase directory for static review")
    scan_parser.add_argument(
        "--live", action="store_true",
        help="Use the real Claude API instead of the free mock analyzer (requires ANTHROPIC_API_KEY)",
    )
    scan_parser.add_argument("--model", default=DEFAULT_LIVE_MODEL, help=f"Model to use with --live (default: {DEFAULT_LIVE_MODEL})")
    scan_parser.add_argument(
        "--internet-facing", action="store_true",
        help="Treat all findings as internet-facing for exploitability/priority assessment",
    )
    scan_parser.add_argument("--out-dir", default="./sectriage-report", help="Directory to write report.json/report.html into")
    scan_parser.set_defaults(func=cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
