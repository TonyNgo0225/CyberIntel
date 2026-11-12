import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

import inventory_monitor as monitor


class InventoryMonitorTests(unittest.TestCase):
    def test_app_list_reads_only_column_a_after_header(self):
        service = MagicMock()
        service.spreadsheets().values().get().execute.return_value = {
            "values": [[".net"], ["Windows 11"], [""], [".NET"]]
        }

        apps = monitor._read_app_list(service, "sheet-id")

        self.assertEqual(
            apps,
            [
                {"name": ".net", "terms": [".net"]},
                {"name": "Windows 11", "terms": ["Windows 11"]},
            ],
        )
        self.assertEqual(
            service.spreadsheets().values().get.call_args.kwargs["range"],
            "'App List'!A2:A",
        )

    def test_email_list_reads_only_column_b_after_header(self):
        service = MagicMock()
        service.spreadsheets().values().get().execute.return_value = {
            "values": [["alerts@example.com"], [""], ["ops@example.org"]]
        }

        emails = monitor._read_email_addresses(service, "sheet-id")

        self.assertEqual(emails, ["alerts@example.com", "ops@example.org"])
        self.assertEqual(
            service.spreadsheets().values().get.call_args.kwargs["range"],
            "'Emails'!B2:B",
        )

    def test_cve_headers_migrate_the_existing_five_column_schema(self):
        service = MagicMock()
        service.spreadsheets().values().get().execute.return_value = {
            "values": [monitor.CVE_HEADERS[:5]]
        }

        monitor._ensure_headers(service, "sheet-id", "CVEs", monitor.CVE_HEADERS)

        update = service.spreadsheets().values().update.call_args.kwargs
        self.assertEqual(update["range"], "'CVEs'!A1:H1")
        self.assertEqual(update["body"]["values"], [monitor.CVE_HEADERS])

    def test_app_match_uses_word_boundaries(self):
        apps = [{"name": "Windows 11", "terms": ["Windows 11"]}]

        self.assertEqual(
            monitor._match_assets("A flaw affects Windows 11 systems.", apps),
            ["Windows 11"],
        )
        self.assertEqual(
            monitor._match_assets("A flaw affects Windows 110 systems.", apps),
            [],
        )

    def test_duplicate_cve_findings_keep_the_highest_severity_and_all_apps(self):
        alerts = monitor._new_alerts(
            [],
            [
                {
                    "identifier": "CVE-2025-12345",
                    "assets": ["Windows 10"],
                    "link": "https://example.invalid/medium",
                    "found_at": "time",
                    "severity": "Medium",
                },
                {
                    "identifier": "CVE-2025-12345",
                    "assets": ["Windows 11"],
                    "link": "https://example.invalid/critical",
                    "found_at": "time",
                    "severity": "Critical",
                },
            ],
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "Critical")
        self.assertEqual(alerts[0]["assets"], ["Windows 10", "Windows 11"])

    def test_app_list_change_rechecks_recent_article_state(self):
        article = {
            "link": "https://example.invalid/article",
            "content_hash": "abc123",
        }

        self.assertNotEqual(
            monitor._state_key(article, "apps-one"),
            monitor._state_key(article, "apps-two"),
        )
        self.assertEqual(
            monitor._state_key(article, "apps-one"),
            monitor._state_key(article, "apps-one"),
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
                "severity": "Critical",
            },
            {
                "identifier": "CVE-2024-0012",
                "assets": ["Asset B"],
                "link": "https://article/2",
                "found_at": "time",
                "severity": "Medium",
            },
            {
                "identifier": "CVE-2024-0002",
                "assets": ["Asset A"],
                "link": "https://article/1",
                "found_at": "time",
                "severity": "Critical",
            },
            {
                "identifier": "CVE-2020-1234",
                "assets": ["Existing product"],
                "link": "https://duplicate",
                "found_at": "time",
                "severity": "High",
            },
        ]

        count = monitor._append_alerts_in_order(
            service, "spreadsheet-id", "CVEs", existing, alerts
        )

        self.assertEqual(count, 3)
        written = service.spreadsheets().values().append.call_args.kwargs
        self.assertEqual(written["range"], "'CVEs'!A:H")
        self.assertEqual(
            written["body"]["values"],
            [
                [9, "CVE-2024-0002", "Asset A", "time", "https://article/1", "Critical", "Yes", "Yes"],
                [10, "CVE-2024-0012", "Asset B", "time", "https://article/2", "Medium", "Yes", ""],
                [11, "CVE-2025-9999", "Asset C", "time", "https://article/3", "Critical", "Yes", "Yes"],
            ],
        )

    def test_existing_cve_is_updated_without_appending_a_duplicate(self):
        service = MagicMock()
        existing = [
            ["1", "CVE-2025-12345", "Example Gateway", "old date", "old link"]
        ]
        alert = {
            "identifier": "CVE-2025-12345",
            "assets": ["Example Gateway"],
            "link": "https://example.invalid/zero-day",
            "found_at": "new date",
            "severity": "Critical",
        }

        count = monitor._append_alerts_in_order(
            service, "spreadsheet-id", "CVEs", existing, [alert]
        )

        self.assertEqual(count, 0)
        service.spreadsheets().values().append.assert_not_called()
        update = service.spreadsheets().values().update.call_args.kwargs
        self.assertEqual(update["range"], "'CVEs'!C2:H2")
        self.assertEqual(
            update["body"]["values"],
            [["Example Gateway", "new date", "https://example.invalid/zero-day", "Critical", "Yes", "Yes"]],
        )

    def test_sent_critical_zero_day_is_not_alerted_again(self):
        existing = [
            [
                "1",
                "CVE-2025-12345",
                "Example Gateway",
                "date",
                "link",
                "Critical",
                "Yes",
                "Yes",
            ]
        ]
        alert = {
            "identifier": "CVE-2025-12345",
            "assets": ["Example Gateway"],
            "link": "new link",
            "found_at": "new date",
            "severity": "Critical",
        }

        self.assertEqual(monitor._new_alerts(existing, [alert]), [])

    @patch("inventory_monitor.cyberintel.fetch")
    @patch(
        "inventory_monitor.cyberintel.analyze_article",
        return_value=(
            {
                "affected_products": ["Example Inc Gateway"],
                "cves": ["CVE-2025-12345"],
                "summary": "A fictional zero-day issue.",
                "severity": "Critical",
                "zero_day": True,
                "zero_day_evidence": "zero-day vulnerability",
            },
            "Google AI Studio",
        ),
    )
    def test_zero_day_cve_alert_requires_an_app_list_match(self, analyze, fetch):
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
            "text": "TEST ONLY: a zero-day vulnerability affects a fictional gateway.",
        }
        apps = [
            {
                "name": "Example Gateway",
                "terms": ["Example Gateway", "Example Inc Gateway"],
            }
        ]

        alerts, provider, status = monitor._process_article(
            article, "Synthetic source", apps, {}
        )

        self.assertEqual(provider, "Google AI Studio")
        self.assertEqual(status, "matched zero-day CVE")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["identifier"], "CVE-2025-12345")
        self.assertEqual(alerts[0]["assets"], ["Example Gateway"])
        self.assertEqual(alerts[0]["severity"], "Critical")

    @patch("inventory_monitor.cyberintel.fetch")
    @patch(
        "inventory_monitor.cyberintel.analyze_article",
        return_value=(
            {
                "affected_products": ["Example Gateway"],
                "cves": ["CVE-2025-12345"],
                "severity": "Critical",
                "zero_day": False,
                "zero_day_evidence": "",
            },
            "Google AI Studio",
        ),
    )
    def test_non_zero_day_and_malware_articles_are_not_findings(self, analyze, fetch):
        article = {
            "link": "https://example.invalid/malware",
            "title": "Synthetic ransomware story",
            "text": "TEST ONLY: ransomware affects Example Gateway.",
        }
        apps = [{"name": "Example Gateway", "terms": ["Example Gateway"]}]

        alerts, _, status = monitor._process_article(
            article, "Synthetic source", apps, {}
        )

        self.assertEqual(alerts, [])
        self.assertEqual(status, "not a confirmed zero-day")
        fetch.assert_not_called()

    @patch("inventory_monitor.cyberintel.fetch")
    @patch(
        "inventory_monitor.cyberintel.analyze_article",
        return_value=(
            {
                "cves": ["CVE-2025-12345"],
                "severity": "Critical",
                "zero_day": True,
                "zero_day_evidence": "zero-day vulnerability",
            },
            "Google AI Studio",
        ),
    )
    def test_zero_day_claim_requires_verbatim_article_evidence(self, analyze, fetch):
        article = {
            "link": "https://example.invalid/article",
            "title": "Synthetic test article",
            "text": "TEST ONLY: a severe flaw was reported.",
        }
        apps = [{"name": "Example Gateway", "terms": ["Example Gateway"]}]

        alerts, _, status = monitor._process_article(
            article, "Synthetic source", apps, {}
        )

        self.assertEqual(alerts, [])
        self.assertEqual(status, "not a confirmed zero-day")
        fetch.assert_not_called()

    @patch("inventory_monitor._send_messages")
    @patch("inventory_monitor._read_tab_values")
    @patch("inventory_monitor.cyberintel._sheet_service")
    def test_daily_report_includes_yesterday_local_noncritical_zero_days(
        self, sheet_service, read_values, send_messages
    ):
        service = MagicMock()
        sheet_service.return_value = service
        read_values.side_effect = [
            [["first@example.com"]],
            [
                [
                    "1",
                    "CVE-2025-12345",
                    "CoolGPT",
                    "2026-11-11T07:30:00+00:00",
                    "https://example.invalid/zero-day",
                    "Medium",
                    "Yes",
                ],
                [
                    "2",
                    "CVE-2025-12346",
                    "EpicGPT",
                    "2026-11-11T08:30:00+00:00",
                    "https://example.invalid/today",
                    "Critical",
                    "Yes",
                ],
                [
                    "3",
                    "CVE-2025-12347",
                    "OldGPT",
                    "2026-11-11T07:30:00+00:00",
                    "https://example.invalid/not-zero-day",
                    "High",
                    "No",
                ],
            ],
        ]
        now = datetime(2026, 11, 11, 8, 0, tzinfo=ZoneInfo("America/Los_Angeles"))

        count = monitor.run_daily_report(
            "sheet-id", "credentials.json", now=now
        )

        self.assertEqual(count, 1)
        self.assertEqual(
            [call.args[3] for call in read_values.call_args_list],
            ["B2:B", "A2:H"],
        )
        subject, body = send_messages.call_args.args[1:3]
        self.assertEqual(subject, "Report for 11/10/26")
        self.assertIn("Vulnerability discovered affecting CoolGPT", body)
        self.assertNotIn("EpicGPT", body)
        self.assertNotIn("OldGPT", body)

    @patch("inventory_monitor._send_messages")
    @patch("inventory_monitor._read_email_addresses", return_value=["first@example.com"])
    def test_hourly_email_sends_one_message_for_each_critical_finding(
        self, read_emails, send_messages
    ):
        service = MagicMock()
        alerts = [
            {
                "identifier": "CVE-2025-12345",
                "assets": ["Windows 10"],
                "link": "https://example.invalid/one",
                "severity": "Critical",
            },
            {
                "identifier": "CVE-2025-12346",
                "assets": ["Windows 11"],
                "link": "https://example.invalid/two",
                "severity": "Medium",
            },
        ]

        count = monitor._send_critical_alerts(service, "sheet-id", alerts, "Emails")

        self.assertEqual(count, 1)
        read_emails.assert_called_once_with(service, "sheet-id", "Emails")
        self.assertEqual(send_messages.call_count, 1)
        self.assertEqual(
            monitor._format_alert_timestamp(
                datetime(2026, 11, 12, 1, 0, tzinfo=timezone.utc)
            ),
            "11/11/26 5:00 P.M",
        )
        subject, body = send_messages.call_args.args[1:3]
        self.assertTrue(subject.startswith("Critical Zero Day Vulnerability Found ("))
        self.assertIn("CVE: CVE-2025-12345", body)
        self.assertNotIn("CVE-2025-12346", body)


if __name__ == "__main__":
    unittest.main()
