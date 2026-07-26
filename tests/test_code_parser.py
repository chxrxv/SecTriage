import os
import unittest

from sectriage.models import SourceTool
from sectriage.parsers import scan_codebase

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable_app")


def _find(findings, file_path, line, vuln_pattern=None):
    for f in findings:
        if f.file_path and f.file_path.replace("\\", "/") == file_path and f.line_number == line:
            if vuln_pattern is None or f.vuln_pattern == vuln_pattern:
                return f
    return None


class TestCodeParser(unittest.TestCase):
    def setUp(self):
        self.findings = scan_codebase(FIXTURE_DIR)

    def test_source_tool_is_code_review(self):
        self.assertTrue(all(f.source_tool == SourceTool.CODE_REVIEW for f in self.findings))

    def test_every_finding_has_file_and_line(self):
        for f in self.findings:
            self.assertIsNotNone(f.file_path)
            self.assertIsNotNone(f.line_number)

    def test_detects_sql_injection_fstring(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 39, "sql_injection"))

    def test_detects_sql_injection_concat(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 48, "sql_injection"))

    def test_detects_hardcoded_stripe_key(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 25, "hardcoded_secret"))

    def test_detects_aws_key(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 26, "hardcoded_secret"))

    def test_detects_pickle_deserialization(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 79, "insecure_deserialization"))

    def test_detects_unsafe_yaml_load(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 85, "insecure_deserialization"))

    def test_detects_eval_via_ast(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 98, "code_injection"))

    def test_detects_path_traversal(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 104, "path_traversal"))

    def test_detects_ssrf(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 121, "ssrf"))

    def test_detects_command_injection_via_ast(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 128, "command_injection"))

    def test_detects_missing_auth_on_sensitive_route(self):
        self.assertIsNotNone(_find(self.findings, "app.py", 132, "missing_auth_check"))

    def test_does_not_flag_parameterized_query(self):
        self.assertIsNone(_find(self.findings, "app.py", 57))

    def test_does_not_flag_env_loaded_secret(self):
        self.assertIsNone(_find(self.findings, "app.py", 27))

    def test_does_not_flag_safeloader_yaml(self):
        self.assertIsNone(_find(self.findings, "app.py", 91))

    def test_does_not_flag_sanitized_path(self):
        self.assertIsNone(_find(self.findings, "app.py", 113))

    def test_misses_multiline_sql_injection_known_limitation(self):
        # Documents a known limitation: the scanner is line-based and cannot
        # see the taint from `query = ... + post_id` (line 66) into the
        # `cursor.execute(query)` call on the following line.
        self.assertIsNone(_find(self.findings, "app.py", 66))

    def test_detects_js_hardcoded_secret(self):
        self.assertIsNotNone(_find(self.findings, "static/app.js", 4, "hardcoded_secret"))

    def test_detects_js_innerhtml_xss(self):
        self.assertIsNotNone(_find(self.findings, "static/app.js", 8, "xss"))

    def test_does_not_flag_js_textcontent(self):
        self.assertIsNone(_find(self.findings, "static/app.js", 13))

    def test_detects_js_document_write_xss(self):
        self.assertIsNotNone(_find(self.findings, "static/app.js", 17, "xss"))

    def test_detects_js_eval(self):
        self.assertIsNotNone(_find(self.findings, "static/app.js", 21, "insecure_deserialization"))

    def test_detects_js_ssrf(self):
        self.assertIsNotNone(_find(self.findings, "static/app.js", 25, "ssrf"))

    def test_known_false_positive_on_allowlisted_fetch(self):
        # Documents a known limitation in the other direction: the scanner has
        # no data-flow analysis, so it cannot see that userUrl was validated
        # against an allowlist a few lines above — it flags this line anyway.
        self.assertIsNotNone(_find(self.findings, "static/app.js", 33, "ssrf"))


if __name__ == "__main__":
    unittest.main()
