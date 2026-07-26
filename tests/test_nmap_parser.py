import os
import unittest

from sectriage.models import Severity, SourceTool
from sectriage.parsers import parse_nmap

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "nmap_sample.xml")


class TestNmapParser(unittest.TestCase):
    def setUp(self):
        self.findings = parse_nmap(FIXTURE)

    def test_finds_all_open_ports(self):
        # 6 ports declared open in the fixture, plus 1 host-script vuln finding
        assets = {f.affected_asset for f in self.findings}
        self.assertIn("198.51.100.23 (demo-target.example.com):21/tcp", assets)
        self.assertIn("198.51.100.23 (demo-target.example.com):22/tcp", assets)
        self.assertIn("198.51.100.23 (demo-target.example.com):23/tcp", assets)
        self.assertIn("198.51.100.23 (demo-target.example.com):80/tcp", assets)
        self.assertIn("198.51.100.23 (demo-target.example.com):443/tcp", assets)
        self.assertIn("198.51.100.23 (demo-target.example.com):3306/tcp", assets)

    def test_source_tool_is_nmap(self):
        self.assertTrue(all(f.source_tool == SourceTool.NMAP for f in self.findings))

    def test_telnet_flagged_high_severity(self):
        telnet = next(f for f in self.findings if ":23/tcp" in f.affected_asset)
        self.assertEqual(telnet.severity, Severity.HIGH)

    def test_vsftpd_backdoor_script_escalates_to_critical(self):
        ftp = next(f for f in self.findings if ":21/tcp" in f.affected_asset)
        self.assertEqual(ftp.severity, Severity.CRITICAL)
        self.assertIn("CVE-2011-2523", ftp.raw_evidence)

    def test_benign_web_port_defaults_low(self):
        http = next(f for f in self.findings if ":80/tcp" in f.affected_asset)
        self.assertEqual(http.severity, Severity.LOW)

    def test_risky_service_defaults_medium(self):
        mysql = next(f for f in self.findings if ":3306/tcp" in f.affected_asset)
        self.assertEqual(mysql.severity, Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
