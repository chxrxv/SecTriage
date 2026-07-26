import os
import unittest

from sectriage.models import Severity, SourceTool
from sectriage.parsers import parse_zap

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "zap_sample.json")


class TestZapParser(unittest.TestCase):
    def setUp(self):
        self.findings = parse_zap(FIXTURE)

    def test_finds_all_alerts(self):
        self.assertEqual(len(self.findings), 5)

    def test_source_tool_is_zap(self):
        self.assertTrue(all(f.source_tool == SourceTool.ZAP for f in self.findings))

    def test_sql_injection_is_high_severity(self):
        sqli = next(f for f in self.findings if "SQL Injection" in f.description)
        self.assertEqual(sqli.severity, Severity.HIGH)
        self.assertIn("search?q=widget", sqli.affected_asset)

    def test_csrf_is_medium_severity(self):
        csrf = next(f for f in self.findings if "CSRF" in f.description)
        self.assertEqual(csrf.severity, Severity.MEDIUM)

    def test_missing_header_is_low_severity(self):
        header = next(f for f in self.findings if "X-Content-Type-Options" in f.description)
        self.assertEqual(header.severity, Severity.LOW)
        self.assertIn("2 instance", header.description)

    def test_evidence_includes_instance_details(self):
        xss = next(f for f in self.findings if "Cross Site Scripting" in f.description)
        self.assertIn("param=name", xss.raw_evidence)


if __name__ == "__main__":
    unittest.main()
