import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import cyberintel as app


RSS = b"""
<rss>
  <channel>
    <item>
      <link>https://example.org/post</link>
      <description>
        CVE-2025-12345 and CVE-2025-12345
      </description>
    </item>
  </channel>
</rss>
"""

RECORD = {
    "cveMetadata": {
        "datePublished": "2025-01-02T00:00:00Z"
    },
    "containers": {
        "cna": {
            "affected": [
                {
                    "vendor": "Acme",
                    "product": "Widget"
                }
            ]
        }
    }
}


class CollectorTests(unittest.TestCase):
    def test_atom(self):
        data = b"""
        <feed xmlns="http://www.w3.org/2005/Atom">
          <entry>
            <link rel="self" href="https://example.org/api"/>
            <link href="https://example.org/article"/>
            <summary>CVE-2025-12345</summary>
          </entry>
        </feed>
        """

        articles = app.parse_feed(data)

        self.assertEqual(
            articles[0][0],
            "https://example.org/article"
        )

    @patch("cyberintel.fetch")
    def test_collect_enriches_and_deduplicates(self, fetch):
        fetch.side_effect = [
            RSS,
            json.dumps(RECORD).encode(),
            RSS
        ]

        rows, failures = app.collect(
            [{"url": "https://example.org/feed"}] * 2
        )

        self.assertEqual(failures, 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0][1:4],
            [
                "CVE-2025-12345",
                "Acme Widget",
                "2025-01-02T00:00:00Z"
            ]
        )

    @patch("cyberintel.fetch")
    def test_lookup_failure_is_retryable_next_run(self, fetch):
        fetch.side_effect = [
            RSS,
            ValueError("unavailable")
        ]

        rows, failures = app.collect(
            [{"url": "https://example.org/feed"}]
        )

        self.assertEqual(rows, [])
        self.assertEqual(failures, 1)

    def test_sheet_dedup(self):
        rows = [
            [
                "https://a",
                "CVE-2025-12345",
                "Acme",
                "date",
                "now"
            ],
            [
                "https://b",
                "CVE-2025-12345",
                "Acme",
                "date",
                "now"
            ]
        ]

        self.assertEqual(
            app.new_rows(rows + rows, rows[:1]),
            rows[1:]
        )

    def test_unknown_and_rejected(self):
        self.assertEqual(
            app.cve_details({}),
            ("Unknown", "Unknown")
        )

        rejected = {
            "cveMetadata": {
                "state": "REJECTED"
            }
        }

        self.assertEqual(
            app.cve_details(rejected)[0],
            "Rejected CVE"
        )

    def test_csv_formula_protection(self):
        self.assertEqual(
            app.csv_safe("=1+1"),
            "'=1+1"
        )

    def test_article_html_removes_script_content(self):
        title, text = app.parse_article_html(
            b"<html><title>Threat update</title><script>secret()</script>"
            b"<p>CVE-2025-12345 details</p></html>"
        )

        self.assertEqual(title, "Threat update")
        self.assertEqual(text, "Threat update CVE-2025-12345 details")

    @patch("cyberintel._groq_analyze", return_value={"summary": "Analyzed"})
    @patch("cyberintel._gemini_analyze", side_effect=RuntimeError("unavailable"))
    def test_google_failure_uses_groq_backup(self, google, groq):
        analysis, provider = app.analyze_article(
            {"article_text": "A cybersecurity article"},
            google_key="google-key",
            groq_key="groq-key"
        )

        self.assertEqual(analysis["summary"], "Analyzed")
        self.assertEqual(provider, "Groq")
        google.assert_called_once()
        groq.assert_called_once()

    @patch(
        "cyberintel._post_json",
        return_value={
            "candidates": [
                {"content": {"parts": [{"text": '{"summary":"Gemini result"}'}]}}
            ]
        },
    )
    def test_gemini_request(self, post_json):
        result = app._gemini_analyze(
            {"article_text": "Article body"},
            "api-key",
            "gemini-test"
        )

        self.assertEqual(result, {"summary": "Gemini result"})
        args, kwargs = post_json.call_args
        self.assertIn("/models/gemini-test:generateContent", args[0])
        self.assertIn("key=api-key", args[0])
        self.assertEqual(
            args[1]["generationConfig"]["responseMimeType"],
            "application/json"
        )

    @patch(
        "cyberintel._post_json",
        return_value={
            "choices": [{"message": {"content": '{"summary":"Groq result"}'}}]
        },
    )
    def test_groq_request(self, post_json):
        result = app._groq_analyze(
            {"article_text": "Article body"},
            "api-key",
            "groq-test"
        )

        self.assertEqual(result, {"summary": "Groq result"})
        args, kwargs = post_json.call_args
        self.assertEqual(
            args[0],
            "https://api.groq.com/openai/v1/chat/completions"
        )
        self.assertEqual(args[2]["Authorization"], "Bearer api-key")
        self.assertEqual(
            args[1]["response_format"],
            {"type": "json_object"}
        )

    @patch(
        "cyberintel.analyze_article",
        return_value=(
            {
                "headline": "Model headline",
                "published_date": "2025-01-02",
                "summary": "A concise summary",
                "topics": ["ransomware", "healthcare"],
                "threats": ["data theft"],
                "cves": [],
                "severity": "high",
                "recommended_action": "Apply the vendor patch",
            },
            "Google AI Studio",
        )
    )
    @patch("cyberintel.fetch")
    def test_collect_articles_scrapes_and_shapes_analysis(self, fetch, analyze):
        feed = b"""
        <rss><channel><item>
          <title>Feed headline</title>
          <link>https://example.org/article</link>
          <pubDate>2025-01-01</pubDate>
          <description>Article excerpt CVE-2025-12345</description>
        </item></channel></rss>
        """
        fetch.side_effect = [
            feed,
            b"<html><title>Page headline</title><p>Page content</p></html>",
        ]

        rows, failures = app.collect_articles(
            [{"name": "Example", "url": "https://example.org/feed"}]
        )

        self.assertEqual(failures, 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0:4], [
            "https://example.org/article",
            "Example",
            "Model headline",
            "2025-01-02",
        ])
        self.assertEqual(rows[0][5:11], [
            "ransomware; healthcare",
            "data theft",
            "CVE-2025-12345",
            "High",
            "Apply the vendor patch",
            "Google AI Studio",
        ])
        analyze.assert_called_once()

    @patch(
        "cyberintel.collect",
        return_value=(
            [
                [
                    "https://example.org",
                    "CVE-2025-12345",
                    "Acme",
                    "date",
                    "now"
                ]
            ],
            0
        )
    )
    @patch("cyberintel.append_to_sheet")
    def test_default_cli_writes_csv_without_sheet_access(
        self,
        append,
        collect
    ):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "rows.csv"

            result = app.main(["--output", str(output)])

            self.assertEqual(result, 0)
            self.assertIn(
                "CVE-2025-12345",
                output.read_text()
            )
            append.assert_not_called()

    def test_sheet_append_and_header_guard(self):
        api = MagicMock()
        api.get.return_value.execute.return_value = {
            "values": [app.HEADERS]
        }

        build = MagicMock()
        build.return_value.spreadsheets.return_value.values.return_value = api

        account = types.ModuleType(
            "google.oauth2.service_account"
        )
        account.Credentials = MagicMock()

        modules = {
            "google": types.ModuleType("google"),
            "google.oauth2": types.ModuleType("google.oauth2"),
            "google.oauth2.service_account": account,
            "googleapiclient": types.ModuleType("googleapiclient"),
            "googleapiclient.discovery": types.ModuleType(
                "googleapiclient.discovery"
            )
        }
        modules["googleapiclient.discovery"].build = build

        row = [
            "https://a",
            "CVE-2025-12345",
            "Acme",
            "date",
            "now"
        ]

        with patch.dict(sys.modules, modules):
            count = app.append_to_sheet(
                [row],
                "spreadsheet-id",
                "Vulnerabilities",
                "key.json"
            )

            self.assertEqual(count, 1)
            self.assertEqual(
                api.append.call_args.kwargs["valueInputOption"],
                "RAW"
            )
            self.assertEqual(
                api.append.call_args.kwargs["body"],
                {"values": [row]}
            )

            api.get.return_value.execute.return_value = {
                "values": [["Other columns"]]
            }

            with self.assertRaises(ValueError):
                app.append_to_sheet(
                    [row],
                    "spreadsheet-id",
                    "Vulnerabilities",
                    "key.json"
                )

    def test_article_sheet_append_and_header_guard(self):
        api = MagicMock()
        api.get.return_value.execute.side_effect = [
            {"values": [app.ARTICLE_HEADERS]},
            {"values": [["https://old.example/article"]]},
        ]

        build = MagicMock()
        build.return_value.spreadsheets.return_value.values.return_value = api

        account = types.ModuleType("google.oauth2.service_account")
        account.Credentials = MagicMock()
        modules = {
            "google": types.ModuleType("google"),
            "google.oauth2": types.ModuleType("google.oauth2"),
            "google.oauth2.service_account": account,
            "googleapiclient": types.ModuleType("googleapiclient"),
            "googleapiclient.discovery": types.ModuleType(
            "googleapiclient.discovery"
            ),
        }
        modules["googleapiclient.discovery"].build = build
        row = ["https://new.example/article"] + ["value"] * (
            len(app.ARTICLE_HEADERS) - 1
        )

        with patch.dict(sys.modules, modules):
            count = app.append_articles_to_sheet(
                [row],
                "spreadsheet-id",
                "Articles",
                "key.json"
            )

        self.assertEqual(count, 1)
        self.assertEqual(
            api.append.call_args.kwargs["body"],
            {"values": [row]}
        )


if __name__ == "__main__":
    unittest.main()
