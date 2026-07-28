import json
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from sectriage.analyzer.ollama_client import (
    OllamaClient,
    OllamaUnavailableError,
    _parse_json_response,
    is_ollama_available,
)
from sectriage.models import Finding, Priority, Severity, SourceTool

_VALID_TRIAGE_JSON = json.dumps(
    {
        "owasp_category": "A03:2021-Injection",
        "explanation": "SQL built via string concatenation.",
        "exploitability": "High — reachable without auth.",
        "business_impact": "Full database read/write.",
        "remediation": "Use a parameterized query.",
        "priority": "Critical",
        "is_internet_facing": True,
    }
)


def _make_finding():
    return Finding(
        source_tool=SourceTool.CODE_REVIEW,
        severity=Severity.CRITICAL,
        description="SQL injection",
        affected_asset="app.py:39",
        raw_evidence="cursor.execute(...)",
        file_path="app.py",
        line_number=39,
        vuln_pattern="sql_injection",
    )


class TestParseJsonResponse(unittest.TestCase):
    def test_parses_clean_json(self):
        data = _parse_json_response(_VALID_TRIAGE_JSON)
        self.assertEqual(data["owasp_category"], "A03:2021-Injection")

    def test_extracts_json_wrapped_in_prose(self):
        wrapped = f"Sure, here is the triage:\n{_VALID_TRIAGE_JSON}\nLet me know if you need more."
        data = _parse_json_response(wrapped)
        self.assertEqual(data["priority"], "Critical")

    def test_raises_on_garbage(self):
        with self.assertRaises(ValueError):
            _parse_json_response("not json at all, sorry")


class TestOllamaClient(unittest.TestCase):
    def _mock_response(self, body: dict):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(body).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = False
        return mock_resp

    @patch("sectriage.analyzer.ollama_client.urllib.request.urlopen")
    def test_triage_happy_path(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_response(
            {
                "message": {"role": "assistant", "content": _VALID_TRIAGE_JSON},
                "prompt_eval_count": 512,
                "eval_count": 128,
            }
        )

        client = OllamaClient(model="llama3.2:1b")
        result, stats = client.triage(_make_finding(), context="internal")

        self.assertEqual(result.owasp_category, "A03:2021-Injection")
        self.assertEqual(result.priority, Priority.CRITICAL)
        self.assertTrue(result.is_internet_facing)
        self.assertEqual(stats.prompt_tokens, 512)
        self.assertEqual(stats.completion_tokens, 128)

    @patch("sectriage.analyzer.ollama_client.urllib.request.urlopen")
    def test_sends_structured_output_format_and_finding_context(self, mock_urlopen):
        mock_urlopen.return_value = self._mock_response(
            {"message": {"content": _VALID_TRIAGE_JSON}, "prompt_eval_count": 1, "eval_count": 1}
        )

        client = OllamaClient(model="llama3.2:1b")
        client.triage(_make_finding(), context="internet-facing")

        request = mock_urlopen.call_args[0][0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["model"], "llama3.2:1b")
        self.assertIn("format", payload)  # JSON-schema structured output, not free text
        self.assertFalse(payload["stream"])
        user_message = next(m["content"] for m in payload["messages"] if m["role"] == "user")
        self.assertIn("app.py:39", user_message)

    @patch("sectriage.analyzer.ollama_client.urllib.request.urlopen")
    def test_connection_failure_raises_actionable_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        client = OllamaClient(model="llama3.2:1b")
        with self.assertRaises(OllamaUnavailableError) as ctx:
            client.triage(_make_finding(), context="internal")

        self.assertIn("ollama pull", str(ctx.exception))

    @patch("sectriage.analyzer.ollama_client.urllib.request.urlopen")
    def test_is_ollama_available_true(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value = MagicMock()
        self.assertTrue(is_ollama_available())

    @patch("sectriage.analyzer.ollama_client.urllib.request.urlopen")
    def test_is_ollama_available_false_on_connection_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("no route to host")
        self.assertFalse(is_ollama_available())


if __name__ == "__main__":
    unittest.main()
