"""Hourly monitoring of configured cyber news sources against an asset inventory."""

import hashlib
import json
import logging
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import cyberintel

LOG = logging.getLogger("cyberintel.monitor")
CVE_HEADERS = [
    "Number",
    "CVE",
    "Affected Software/Hardware",
    "Date/Time Found",
    "Link",
]
STATE_HEADERS = ["State key", "Article URL", "Checked at", "Result"]
CVE_RE = cyberintel.CVE_RE
MALWARE_RE = re.compile(r"\b(?:malware|ransomware|wiper|trojan|worm|botnet)\b", re.I)
FEEDS = {
    "cyberpress.org": "https://cyberpress.org/feed/",
    "cybersecuritynews.com": "https://cybersecuritynews.com/feed/",
    "thehackernews.com": "https://feeds.feedburner.com/TheHackersNews",
    "databreachtoday.com": "https://www.databreachtoday.com/rss-feeds",
    "darkreading.com": "https://www.darkreading.com/feeds/rss.xml",
    "bleepingcomputer.com": "https://www.bleepingcomputer.com/feed/",
    "theregister.com": "https://www.theregister.com/security/headlines.atom",
    "infosecurity-magazine.com": "https://www.infosecurity-magazine.com/rss/news/",
    "cybersecuritydive.com": "https://www.cybersecuritydive.com/feeds/news/",
}
SNAPSHOT_HOSTS = {"tenable.com"}
UNSUPPORTED_HOSTS = {
    "armis.com": "the CVE list is JavaScript-loaded and has no verified public feed",
    "shodan.io": "Shodan is a search/API platform, not a cybersecurity news feed",
}


def _host(url):
    host = urllib.parse.urlsplit(url).hostname or ""
    return host.lower().removeprefix("www.")


def _extract_urls(values):
    urls = []
    seen = set()
    pattern = re.compile(r"https://[^\s<>|\"']+", re.IGNORECASE)
    for row in values:
        for cell in row:
            for match in pattern.findall(str(cell)):
                url = match.rstrip(".,;)")
                if url not in seen:
                    seen.add(url)
                    urls.append(url)
    return urls


def _read_tab_values(service, spreadsheet_id, tab, range_suffix):
    quoted = "'" + tab.replace("'", "''") + "'"
    result = (
        service.spreadsheets()
        .values()
        .get(spreadsheetId=spreadsheet_id, range=f"{quoted}!{range_suffix}")
        .execute()
    )
    return result.get("values", [])


def _get_or_create_tab(service, spreadsheet_id, tab):
    spreadsheets = service.spreadsheets()
    metadata = spreadsheets.get(
        spreadsheetId=spreadsheet_id, fields="sheets.properties.title"
    ).execute()
    names = {
        sheet.get("properties", {}).get("title")
        for sheet in metadata.get("sheets", [])
    }
    if tab not in names:
        spreadsheets.batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={"requests": [{"addSheet": {"properties": {"title": tab}}}]},
        ).execute()


def _ensure_headers(service, spreadsheet_id, tab, headers):
    quoted = "'" + tab.replace("'", "''") + "'"
    end = chr(ord("A") + len(headers) - 1)
    values = service.spreadsheets().values()
    current = (
        values.get(
            spreadsheetId=spreadsheet_id,
            range=f"{quoted}!A1:{end}1",
        )
        .execute()
        .get("values", [])
    )
    if current:
        if current[0] != headers:
            raise ValueError(
                f"Sheet tab {tab!r} must have these exact headers in row 1: "
                + ", ".join(headers)
            )
    else:
        values.update(
            spreadsheetId=spreadsheet_id,
            range=f"{quoted}!A1:{end}1",
            valueInputOption="RAW",
            body={"values": [headers]},
        ).execute()


def _append_rows(service, spreadsheet_id, tab, headers, rows):
    if not rows:
        return 0
    quoted = "'" + tab.replace("'", "''") + "'"
    end = chr(ord("A") + len(headers) - 1)
    service.spreadsheets().values().append(
        spreadsheetId=spreadsheet_id,
        range=f"{quoted}!A:{end}",
        valueInputOption="RAW",
        insertDataOption="INSERT_ROWS",
        body={"values": rows},
    ).execute()
    return len(rows)


def _read_inventory(path):
    with Path(path).open(encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict) or not isinstance(data.get("assets"), list):
        raise ValueError(f"{path} must contain an 'assets' list")
    assets = []
    for index, asset in enumerate(data["assets"], start=1):
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            raise ValueError(f"Asset {index} in {path} must have a string 'name'")
        name = " ".join(asset["name"].split())
        if not name:
            raise ValueError(f"Asset {index} in {path} has an empty name")
        aliases = asset.get("aliases", [])
        if not isinstance(aliases, list) or not all(
            isinstance(alias, str) for alias in aliases
        ):
            raise ValueError(f"Asset {name!r} aliases must be a list of strings")
        terms = [name, *(alias.strip() for alias in aliases if alias.strip())]
        vendor = asset.get("vendor")
        if isinstance(vendor, str) and vendor.strip():
            terms.append(f"{vendor.strip()} {name}")
        assets.append({"name": name, "terms": list(dict.fromkeys(terms))})
    if not assets:
        raise ValueError(
            f"{path} has no assets. Add the software and hardware you use before "
            "enabling the hourly inventory scan."
        )
    return assets


def _match_assets(text, assets):
    haystack = " ".join(str(text or "").split()).casefold()
    matches = []
    for asset in assets:
        for term in asset["terms"]:
            term = " ".join(term.split())
            if not term:
                continue
            pattern = (
                r"(?<![A-Za-z0-9])"
                + re.escape(term).replace(r"\ ", r"\s+")
                + r"(?![A-Za-z0-9])"
            )
            if re.search(pattern, haystack, re.IGNORECASE):
                matches.append(asset["name"])
                break
    return matches


def _cve_products(record):
    cna = record.get("containers", {}).get("cna", {})
    products = []
    for affected in cna.get("affected", []):
        vendor = str(affected.get("vendor", "")).strip()
        product = str(affected.get("product", "")).strip()
        if vendor or product:
            products.append(" ".join(part for part in (vendor, product) if part))
        for version in affected.get("versions", []):
            version_value = str(version.get("version", "")).strip()
            if version_value and product:
                products.append(f"{product} {version_value}")
    descriptions = cna.get("descriptions", [])
    products.extend(
        str(description.get("value", "")).strip()
        for description in descriptions
        if description.get("value")
    )
    return products


def _asset_matches_for_cve(record, analysis, article_text, assets):
    products = _cve_products(record)
    products.extend(cyberintel._string_list(analysis.get("affected_products")).split(";"))
    product_matches = _match_assets(" ; ".join(products), assets)
    if product_matches:
        return product_matches
    if products:
        return []
    return _match_assets(article_text, assets)


def _state_key(article, inventory_fingerprint):
    if article.get("content_hash"):
        content_key = f"{article['link']}#content-{article['content_hash']}"
    else:
        content_key = article["link"]
    return f"{content_key}#inventory-{inventory_fingerprint}"


def _resolve_sources(urls):
    feeds = []
    pages = []
    seen_feeds = set()
    seen_pages = set()
    for url in urls:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            LOG.warning("Skipping non-HTTPS or invalid source URL: %s", url)
            continue
        host = _host(url)
        if host in FEEDS:
            feed = FEEDS[host]
            if feed not in seen_feeds:
                seen_feeds.add(feed)
                feeds.append(
                    {"name": host, "url": feed}
                )
            path = parsed.path.rstrip("/")
            is_listing = path in (
                "",
                "/news",
                "/latest-news",
                "/security/headlines.atom",
                "/news/index.html",
            )
            is_darkreading_article = host == "darkreading.com" and path.startswith(
                "/cybersecurity-analytics/"
            )
            if path and not is_listing and (
                is_darkreading_article or host == "darkreading.com"
            ):
                if url not in seen_pages:
                    seen_pages.add(url)
                    pages.append(
                        {"name": f"{host} article", "url": url}
                    )
            continue
        if any(host == domain or host.endswith("." + domain) for domain in SNAPSHOT_HOSTS):
            if url not in seen_pages:
                seen_pages.add(url)
                pages.append({"name": f"{host} page", "url": url})
            continue
        unsupported = next(
            (
                reason
                for domain, reason in UNSUPPORTED_HOSTS.items()
                if host == domain or host.endswith("." + domain)
            ),
            None,
        )
        if unsupported:
            LOG.warning("Skipping %s: %s", url, unsupported)
        else:
            LOG.warning("Skipping unsupported website URL: %s", url)
    return feeds, pages


def _read_seen_state(service, spreadsheet_id, state_tab):
    _get_or_create_tab(service, spreadsheet_id, state_tab)
    _ensure_headers(service, spreadsheet_id, state_tab, STATE_HEADERS)
    rows = _read_tab_values(service, spreadsheet_id, state_tab, "A2:D")
    return {row[0] for row in rows if row}


def _read_cve_rows(service, spreadsheet_id, cve_tab):
    _get_or_create_tab(service, spreadsheet_id, cve_tab)
    _ensure_headers(service, spreadsheet_id, cve_tab, CVE_HEADERS)
    return _read_tab_values(service, spreadsheet_id, cve_tab, "A2:E")


def _cve_order(cve):
    match = CVE_RE.fullmatch(str(cve).upper())
    if not match:
        return 1, str(cve).casefold()
    year, number = re.fullmatch(r"CVE-(\d{4})-(\d+)", str(cve).upper()).groups()
    return 0, int(year), int(number)


def _append_alerts_in_order(service, spreadsheet_id, cve_tab, existing, alerts):
    existing_cves = set()
    malware_links = set()
    max_number = 0
    for row in existing:
        if not row:
            continue
        number = str(row[0]).strip()
        if number.isdigit():
            max_number = max(max_number, int(number))
        identifier = row[1].strip().upper() if len(row) > 1 else ""
        if CVE_RE.fullmatch(identifier):
            existing_cves.add(identifier)
        elif identifier.startswith("MALWARE") and len(row) > 4:
            malware_links.add(row[4])

    unique_alerts = {}
    for alert in alerts:
        identifier = alert["identifier"].upper()
        key = ("CVE", identifier) if CVE_RE.fullmatch(identifier) else (
            "MALWARE",
            alert["link"],
        )
        if identifier in existing_cves or alert["link"] in malware_links:
            continue
        unique_alerts.setdefault(key, alert)

    sorted_alerts = sorted(
        unique_alerts.values(), key=lambda alert: _cve_order(alert["identifier"])
    )
    rows = []
    for offset, alert in enumerate(sorted_alerts, start=1):
        rows.append(
            [
                max_number + offset,
                alert["identifier"],
                "; ".join(sorted(set(alert["assets"]), key=str.casefold)),
                alert["found_at"],
                alert["link"],
            ]
        )
    return _append_rows(service, spreadsheet_id, cve_tab, CVE_HEADERS, rows)


def _fetch_article_page(url):
    page_title, page_text = cyberintel.parse_article_html(cyberintel.fetch(url))
    digest = hashlib.sha256(page_text.encode("utf-8")).hexdigest()[:16]
    return {
        "link": url,
        "title": page_title,
        "published": "",
        "text": page_text,
        "content_hash": digest,
    }


def _process_article(article, source_name, assets, cve_cache):
    text = article["text"]
    title = article.get("title", "")
    analysis, provider = cyberintel.analyze_article(
        {
            "source": source_name,
            "link": article["link"],
            "feed_title": title,
            "feed_published": article.get("published", ""),
            "article_text": text[: cyberintel.MAX_ARTICLE_TEXT],
        }
    )
    if not isinstance(analysis, dict):
        raise RuntimeError("AI provider returned an invalid article analysis")

    analyzed_products = cyberintel._string_list(analysis.get("affected_products"))
    evidence = " ".join(
        (
            text,
            title,
            cyberintel._string_list(analysis.get("summary")),
            analyzed_products,
        )
    )
    article_matches = _match_assets(evidence, assets)
    cves = sorted(
        set(
            CVE_RE.findall(
                " ".join(
                    (
                        text.upper(),
                        cyberintel._string_list(analysis.get("cves")).upper(),
                    )
                )
            )
        ),
        key=_cve_order,
    )
    alerts = []
    failed_lookup = False
    for cve in cves:
        if cve not in cve_cache:
            try:
                cve_cache[cve] = json.loads(
                    cyberintel.fetch(f"https://cveawg.mitre.org/api/cve/{cve}")
                )
            except Exception as error:
                LOG.error("CVE lookup %s failed: %s", cve, error)
                cve_cache[cve] = None
                failed_lookup = True
        record = cve_cache[cve]
        if record is None:
            continue
        matched_assets = _asset_matches_for_cve(record, analysis, evidence, assets)
        if matched_assets:
            alerts.append(
                {
                    "identifier": cve,
                    "assets": matched_assets,
                    "link": article["link"],
                    "found_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
            )

    severity = str(analysis.get("severity", "")).strip().casefold()
    malware_value = analysis.get("is_malware")
    malware_flag = malware_value is True or (
        isinstance(malware_value, str) and malware_value.strip().casefold() == "true"
    )
    threats = cyberintel._string_list(analysis.get("threats"))
    malware_flag = malware_flag or bool(MALWARE_RE.search(threats + " " + title))
    if severity in ("high", "critical") and malware_flag and article_matches and not cves:
        alerts.append(
            {
                "identifier": "MALWARE (no CVE)",
                "assets": article_matches,
                "link": article["link"],
                "found_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        )

    if failed_lookup:
        raise RuntimeError("One or more CVE lookups failed; article will be retried")
    status = "matched" if alerts else "no tracked asset match"
    return alerts, provider, status


def run_monitor(
    spreadsheet_id,
    credentials_path,
    inventory_path="inventory.json",
    links_tab="Links",
    cve_tab="CVEs",
    state_tab="ScanState",
    max_articles=5,
):
    if max_articles < 1:
        raise ValueError("max_articles must be greater than zero")
    assets = _read_inventory(inventory_path)
    inventory_fingerprint = hashlib.sha256(
        json.dumps(assets, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    service = cyberintel._sheet_service(credentials_path)
    configured_rows = _read_tab_values(service, spreadsheet_id, links_tab, "A1:Z")
    source_urls = _extract_urls(configured_rows)
    if not source_urls:
        raise ValueError(f"No HTTPS source URLs found in the {links_tab!r} sheet tab")
    feeds, pages = _resolve_sources(source_urls)
    if not feeds and not pages:
        raise ValueError("No supported RSS feeds or article pages found in the Links tab")

    seen_state = _read_seen_state(service, spreadsheet_id, state_tab)
    existing_cves = _read_cve_rows(service, spreadsheet_id, cve_tab)
    cve_cache = {}
    alerts = []
    state_rows = []
    failures = 0
    processed = 0
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for source in feeds:
        try:
            articles = cyberintel.parse_feed_records(cyberintel.fetch(source["url"]))[
                :max_articles
            ]
        except Exception as error:
            LOG.error("Feed %s failed: %s", source["name"], error)
            failures += 1
            continue
        for article in articles:
            key = _state_key(article, inventory_fingerprint)
            if key in seen_state:
                continue
            try:
                page_title, page_text = cyberintel.parse_article_html(
                    cyberintel.fetch(article["link"])
                )
                article["title"] = page_title or article.get("title", "")
                article["text"] = " ".join(
                    part for part in (page_text, article.get("text", "")) if part
                )[: cyberintel.MAX_ARTICLE_TEXT]
            except Exception as error:
                LOG.warning("Article page %s failed; using its feed entry: %s", article["link"], error)
            try:
                found, provider, status = _process_article(
                    article, source["name"], assets, cve_cache
                )
                alerts.extend(found)
                state_rows.append([key, article["link"], checked_at, status])
                seen_state.add(key)
                processed += 1
                LOG.info(
                    "Processed %s with %s: %s",
                    article["link"],
                    provider,
                    status,
                )
            except Exception as error:
                LOG.error("Article analysis %s failed: %s", article["link"], error)
                failures += 1

    for source in pages:
        try:
            article = _fetch_article_page(source["url"])
        except Exception as error:
            LOG.error("Source page %s failed: %s", source["url"], error)
            failures += 1
            continue
        key = _state_key(article, inventory_fingerprint)
        if key in seen_state:
            continue
        try:
            found, provider, status = _process_article(
                article, source["name"], assets, cve_cache
            )
            alerts.extend(found)
            state_rows.append([key, article["link"], checked_at, status])
            seen_state.add(key)
            processed += 1
            LOG.info("Processed %s with %s: %s", article["link"], provider, status)
        except Exception as error:
            LOG.error("Article analysis %s failed: %s", article["link"], error)
            failures += 1

    _append_alerts_in_order(service, spreadsheet_id, cve_tab, existing_cves, alerts)
    _append_rows(service, spreadsheet_id, state_tab, STATE_HEADERS, state_rows)
    LOG.info(
        "Inventory scan complete: %d new article(s) analyzed, %d alert(s) found, "
        "%d article(s) failed",
        processed,
        len(alerts),
        failures,
    )
    return failures
