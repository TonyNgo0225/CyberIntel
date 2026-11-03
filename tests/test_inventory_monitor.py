import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import inventory_monitor as monitor


class InventoryMonitorTests(unittest.TestCase):
    def test_inventory_asset_match_uses_word_boundaries(self):
        assets = [
            {"name": "Windows 11", "terms": ["Windows 11", "Microsoft Windows 11"]}
        ]

        self.assertEqual(
            monitor._match_assets("A flaw affects Microsoft Windows 11 systems.", assets),
            ["Windows 11"],
        )
        self.assertEqual(
            monitor._match_assets("A flaw affects Windows 110 systems.", assets),
            [],
        )

    def test_inventory_must_contain_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text('{"assets":[]}', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "no assets"):
                monitor._read_inventory(path)

    def test_inventory_validates_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text(
                json.dumps({"assets": [{"name": "Example Router", "aliases": "router"}]}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "aliases must be a list"):
                monitor._read_inventory(path)

    def test_inventory_change_rechecks_recent_article_state(self):
        article = {
            "link": "https://example.invalid/article",
            "content_hash": "abc123",
        }

        self.assertNotEqual(
            monitor._state_key(article, "inventory-one"),
            monitor._state_key(article, "inventory-two"),
        )
        self.assertEqual(
            monitor._state_key(article, "inventory-one"),
            monitor._state_key(article, "inventory-one"),
        )

    def test_configured_urls_resolve_to_supported_feeds_and_pages(self):
        feeds, pages = monitor._resolve_sources(
            [
                "https://cyberpress.org/",
                "https://www.databreachtoday.com/latest-news",
                "https://www.darkreading.com/cybersecurity-analytics/example-story",
                "https://www.tenable.com/plugins",
                "https://www.shodan.io/",
            ]
        )

        self.assertEqual(
            [source["url"] for source in feeds],
            [
                "https://cyberpress.org/feed/",
                "https://www.databreachtoday.com/rss-feeds",
                "https://www.darkreading.com/feeds/rss.xml",
            ],
        )
        self.assertEqual(
            [source["url"] for source in pages],
            [
                "https://www.darkreading.com/cybersecurity-analytics/example-story",
                "https://www.tenable.com/plugins",
            ],
        )

    def test_alerts_are_deduplicated_and_numbered_in_cve_order(self):
        service = MagicMock()
        existing = [
            ["8", "CVE-2020-1234", "Existing product", "date", "https://existing"]
        ]
        alerts = [
            {
                "identifier": "CVE-2025-9999",
                "assets": ["Asset C"],
                "link": "https://article/3",
                "found_at": "time",
            },
            {
                "identifier": "CVE-2024-0012",
                "assets": ["Asset B"],
                "link": "https://article/2",
                "found_at": "time",
            },
            {
                "identifier": "CVE-2024-0002",
                "assets": ["Asset A"],
                "link": "https://article/1",
                "found_at": "time",
            },
            {
                "identifier": "CVE-2020-1234",
                "assets": ["Existing product"],
                "link": "https://duplicate",
                "found_at": "time",
            },
        ]

        count = monitor._append_alerts_in_order(
            service, "spreadsheet-id", "CVEs", existing, alerts
        )

        self.assertEqual(count, 3)
        written = service.spreadsheets().values().append.call_args.kwargs
        self.assertEqual(written["range"], "'CVEs'!A:E")
        self.assertEqual(
            written["body"]["values"],
            [
                [9, "CVE-2024-0002", "Asset A", "time", "https://article/1"],
                [10, "CVE-2024-0012", "Asset B", "time", "https://article/2"],
                [11, "CVE-2025-9999", "Asset C", "time", "https://article/3"],
            ],
        )

    @patch("inventory_monitor.cyberintel.fetch")
    @patch(
        "inventory_monitor.cyberintel.analyze_article",
        return_value=(
            {
                "affected_products": ["Example Inc Gateway"],
                "cves": ["CVE-2025-12345"],
                "summary": "A fictional test issue.",
                "severity": "High",
                "threats": [],
                "is_malware": False,
            },
            "Google AI Studio",
        ),
    )
    def test_cve_alert_requires_a_tracked_affected_product(self, analyze, fetch):
        record = {
            "containers": {
                "cna": {
                    "affected": [
                        {"vendor": "Example Inc", "product": "Gateway"}
                    ]
                }
            }
        }
        fetch.return_value = json.dumps(record).encode()
        article = {
            "link": "https://example.invalid/article",
            "title": "Synthetic test article",
            "text": "TEST ONLY: CVE-2025-12345 affects a fictional gateway.",
        }
        assets = [
            {
                "name": "Example Gateway",
                "terms": ["Example Gateway", "Example Inc Gateway"],
            }
        ]

        alerts, provider, status = monitor._process_article(
            article, "Synthetic source", assets, {}
        )

        self.assertEqual(provider, "Google AI Studio")
        self.assertEqual(status, "matched")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["identifier"], "CVE-2025-12345")
        self.assertEqual(alerts[0]["assets"], ["Example Gateway"])

    @patch(
        "inventory_monitor.cyberintel.analyze_article",
        return_value=(
            {
                "affected_products": ["Example Gateway"],
                "cves": [],
                "summary": "A fictional malware story.",
                "severity": "Critical",
                "threats": ["ransomware"],
                "is_malware": True,
            },
            "Google AI Studio",
        ),
    )
    def test_severe_malware_alert_is_logged_for_a_tracked_product(self, analyze):
        article = {
            "link": "https://example.invalid/malware",
            "title": "Synthetic ransomware test",
            "text": "TEST ONLY: ransomware affects a fictional gateway.",
        }
        assets = [{"name": "Example Gateway", "terms": ["Example Gateway"]}]

        alerts, _, status = monitor._process_article(
            article, "Synthetic source", assets, {}
        )

        self.assertEqual(status, "matched")
        self.assertEqual(alerts[0]["identifier"], "MALWARE (no CVE)")
        self.assertEqual(alerts[0]["assets"], ["Example Gateway"])


if __name__ == "__main__":
    unittest.main()
