"""Collect RSS/Atom CVE mentions locally; optionally append them to Google Sheets."""

import argparse
import csv
import html
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

HEADERS = ["Article link", "CVE", "Products affected", "CVE published date", "Added at"]
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
LOG = logging.getLogger("cyberintel")
MAX_RESPONSE = 5 * 1024 * 1024


def fetch(url, attempts=3):
    """Bounded HTTPS fetch with retries for transient errors; TLS stays enabled."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError(f"Only HTTPS URLs are supported: {url}")
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "CyberIntel/0.1 (local RSS collector)"})
            with urllib.request.urlopen(request, timeout=25) as response:
                if urllib.parse.urlsplit(response.url).scheme != "https":
                    raise ValueError("Refusing a non-HTTPS redirect")
                data = response.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise ValueError("Response exceeds 5 MiB limit")
                return data
        except (urllib.error.URLError, TimeoutError) as error:
            retryable = not isinstance(error, urllib.error.HTTPError) or error.code in (429, 500, 502, 503, 504)
            if not retryable or attempt == attempts - 1:
                raise
            time.sleep(2 ** attempt)


def parse_feed(data):
    root = ET.fromstring(data)
    articles = []
    for entry in root.iter():
        if entry.tag.split("}")[-1] not in ("item", "entry"):
            continue
        link = ""
        for child in entry:
            if child.tag.split("}")[-1] == "link":
                if child.get("rel", "alternate") == "alternate":
                    link = child.get("href") or (child.text or "").strip()
                    if link:
                        break
        if urllib.parse.urlsplit(link).scheme == "https":
            text = html.unescape(" ".join(entry.itertext()))
            articles.append((link.split("#", 1)[0], text))
    return articles


def cve_details(record):
    metadata = record.get("cveMetadata", {})
    if metadata.get("state") == "REJECTED":
        return "Rejected CVE", metadata.get("datePublished", "Unknown")
    products = []
    for affected in record.get("containers", {}).get("cna", {}).get("affected", []):
        name = " ".join(str(affected.get(key, "")).strip() for key in ("vendor", "product")).strip()
        if name and name not in products:
            products.append(name)
    return "; ".join(products) or "Unknown", metadata.get("datePublished", "Unknown")


def collect(sources, max_articles=20, fetch_articles=False):
    rows, pairs, cache = [], set(), {}
    failures = 0
    added_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for source in sources:
        try:
            articles = parse_feed(fetch(source["url"]))[:max_articles]
        except Exception as error:
            LOG.error("Feed %s failed: %s", source.get("name", source.get("url")), error)
            failures += 1
            continue
        LOG.info("Checking %d entries from %s", len(articles), source.get("name", source["url"]))
        for link, text in articles:
            if fetch_articles:
                try:
                    text += " " + html.unescape(fetch(link).decode("utf-8", errors="replace"))
                except Exception as error:
                    LOG.error("Article %s failed: %s", link, error)
                    failures += 1
            for cve in sorted(set(CVE_RE.findall(text.upper()))):
