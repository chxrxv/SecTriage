import unittest

from sectriage.models import Finding, Priority, Severity, SourceTool, TriagedFinding, TriageResult
from sectriage.report import deduplicate


def _tf(source_tool, asset, description, owasp_category, priority):
    finding = Finding(
        source_tool=source_tool,
        severity=Severity.HIGH,
        description=description,
        affected_asset=asset,
        raw_evidence="evidence",
    )
    triage = TriageResult(
        finding_id=finding.id,
        owasp_category=owasp_category,
        explanation="explanation",
        exploitability="exploitability",
        business_impact="impact",
        remediation="remediation",
        priority=priority,
    )
    return TriagedFinding(finding=finding, triage=triage)


class TestDedup(unittest.TestCase):
    def test_merges_same_host_same_category_across_tools(self):
        a = _tf(SourceTool.NMAP, "10.0.0.5:443/tcp", "Weak TLS cipher", "A02:2021-Cryptographic Failures", Priority.MEDIUM)
        b = _tf(SourceTool.ZAP, "10.0.0.5:443/tcp", "Weak cipher suite enabled", "A02:2021-Cryptographic Failures", Priority.HIGH)

        result = deduplicate([a, b])

        primaries = [tf for tf in result if tf.triage.duplicate_of is None]
        duplicates = [tf for tf in result if tf.triage.duplicate_of is not None]
        self.assertEqual(len(primaries), 1)
        self.assertEqual(len(duplicates), 1)
        # The higher-priority finding (High) should survive as the primary
        self.assertEqual(primaries[0].triage.priority, Priority.HIGH)
        self.assertEqual(duplicates[0].triage.duplicate_of, primaries[0].finding.id)

    def test_does_not_merge_different_hosts(self):
        a = _tf(SourceTool.NMAP, "10.0.0.5:443/tcp", "Weak TLS cipher", "A02:2021-Cryptographic Failures", Priority.MEDIUM)
        b = _tf(SourceTool.ZAP, "10.0.0.6:443/tcp", "Weak cipher suite enabled", "A02:2021-Cryptographic Failures", Priority.HIGH)

        result = deduplicate([a, b])

        self.assertTrue(all(tf.triage.duplicate_of is None for tf in result))

    def test_does_not_merge_different_categories_on_same_host(self):
        a = _tf(SourceTool.NMAP, "10.0.0.5:80/tcp", "Open port", "A05:2021-Security Misconfiguration", Priority.LOW)
        b = _tf(SourceTool.ZAP, "10.0.0.5:80/tcp", "Reflected XSS", "A03:2021-Injection", Priority.HIGH)

        result = deduplicate([a, b])

        self.assertTrue(all(tf.triage.duplicate_of is None for tf in result))

    def test_merges_nmap_ip_with_zap_hostname_via_resolved_name(self):
        # Nmap identifies the host by IP (with a resolved hostname in
        # parens); ZAP identifies it by hostname via the crawled URL. The
        # normalized key must prefer the hostname or these never correlate.
        nmap_finding = _tf(
            SourceTool.NMAP, "203.0.113.9 (shop.example.com):80/tcp",
            "Open port 80/tcp running http", "A05:2021-Security Misconfiguration", Priority.LOW,
        )
        zap_finding = _tf(
            SourceTool.ZAP, "http://shop.example.com/cart",
            "Cross-Domain Misconfiguration", "A05:2021-Security Misconfiguration", Priority.MEDIUM,
        )

        result = deduplicate([nmap_finding, zap_finding])

        primaries = [tf for tf in result if tf.triage.duplicate_of is None]
        self.assertEqual(len(primaries), 1)
        self.assertEqual(primaries[0].finding.source_tool, SourceTool.ZAP)  # higher priority wins

    def test_no_duplicates_is_a_noop(self):
        a = _tf(SourceTool.CODE_REVIEW, "app.py:10", "SQL injection", "A03:2021-Injection", Priority.CRITICAL)
        result = deduplicate([a])
        self.assertIsNone(result[0].triage.duplicate_of)

    def test_code_review_findings_in_same_file_are_never_merged(self):
        # Regression test: affected_asset for code findings is "file.py:LINE",
        # and naively stripping after ":" (correct for Nmap/ZAP host:port
        # assets) would collapse every finding in the same file sharing an
        # OWASP category into one, wrongly merging distinct vulnerabilities.
        a = _tf(SourceTool.CODE_REVIEW, "app.py:39", "SQL injection (f-string)", "A03:2021-Injection", Priority.CRITICAL)
        b = _tf(SourceTool.CODE_REVIEW, "app.py:48", "SQL injection (concat)", "A03:2021-Injection", Priority.CRITICAL)

        result = deduplicate([a, b])

        self.assertTrue(all(tf.triage.duplicate_of is None for tf in result))


if __name__ == "__main__":
    unittest.main()
