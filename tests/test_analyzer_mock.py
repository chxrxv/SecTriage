import unittest

from sectriage.analyzer import triage_findings
from sectriage.analyzer.mock import mock_triage
from sectriage.models import Finding, Priority, Severity, SourceTool


class TestMockAnalyzer(unittest.TestCase):
    def test_mock_triage_classifies_sql_injection(self):
        finding = Finding(
            source_tool=SourceTool.CODE_REVIEW,
            severity=Severity.CRITICAL,
            description="SQL query built with an f-string",
            affected_asset="app.py:39",
            raw_evidence="cursor.execute(f\"...\")",
            file_path="app.py",
            line_number=39,
            vuln_pattern="sql_injection",
        )
        result, stats = mock_triage(finding, context="internal", simulate_latency=False)

        self.assertEqual(result.owasp_category, "A03:2021-Injection")
        self.assertEqual(result.priority, Priority.CRITICAL)
        self.assertIn("app.py:39", result.remediation)
        self.assertEqual(stats["input_tokens"], 0)  # mock mode costs nothing

    def test_mock_triage_escalates_priority_when_internet_facing(self):
        finding = Finding(
            source_tool=SourceTool.NMAP,
            severity=Severity.HIGH,
            description="Open telnet port",
            affected_asset="10.0.0.1:23/tcp",
            raw_evidence="port 23 open",
        )
        internal_result, _ = mock_triage(finding, context="internal", simulate_latency=False)
        public_result, _ = mock_triage(finding, context="internet-facing", simulate_latency=False)

        self.assertTrue(public_result.is_internet_facing)
        self.assertFalse(internal_result.is_internet_facing)
        self.assertEqual(internal_result.priority, Priority.HIGH)
        self.assertEqual(public_result.priority, Priority.CRITICAL)

    def test_triage_findings_mock_mode_end_to_end(self):
        findings = [
            Finding(
                source_tool=SourceTool.CODE_REVIEW,
                severity=Severity.CRITICAL,
                description="Hardcoded secret",
                affected_asset="app.py:25",
                raw_evidence="STRIPE_API_KEY = \"sk_...\"",
                file_path="app.py",
                line_number=25,
                vuln_pattern="hardcoded_secret",
            ),
        ]
        triaged, metrics = triage_findings(findings, live=False)

        self.assertEqual(len(triaged), 1)
        self.assertEqual(metrics.mode, "mock")
        self.assertEqual(metrics.total_findings, 1)
        self.assertEqual(triaged[0].triage.owasp_category, "A07:2021-Identification and Authentication Failures")


if __name__ == "__main__":
    unittest.main()
