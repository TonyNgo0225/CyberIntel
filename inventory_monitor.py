"""Monitor configured sources for zero-day CVEs affecting the spreadsheet app list."""

import hashlib
import json
import logging
import os
import re
import smtplib
import ssl
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from zoneinfo import ZoneInfo

import cyberintel

LOG = logging.getLogger("cyberintel.monitor")
CVE_HEADERS = [
    "Number",
    "CVE",
    "Affected Software/Hardware",
    "Date/Time Found",
    "Link",
    "Severity",
    "Zero Day",
    "Critical Email Sent",
]
STATE_HEADERS = ["State key", "Article URL", "Checked at", "Result"]
CVE_RE = cyberintel.CVE_RE
ZERO_DAY_RE = re.compile(r"\bzero[\s-]?day\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.IGNORECASE)
PACIFIC = ZoneInfo("America/Los_Angeles")
SEVERITY_RANK = {
    "unknown": 0,
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
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
    if current and current[0]:
        existing_headers = current[0]
        if existing_headers != headers:
            if headers[: len(existing_headers)] != existing_headers:
                raise ValueError(
                    f"Sheet tab {tab!r} must begin with these headers: "
                    + ", ".join(headers)
                )
            values.update(
                spreadsheetId=spreadsheet_id,
                range=f"{quoted}!A1:{end}1",
                valueInputOption="RAW",
                body={"values": [headers]},
            ).execute()
    else:
        values.update(
            spreadsheetId=spreadsheet_id,
            range=f"{quoted}!A1:{end}1",
            valueInputOption="RAW",
            body={"values": [headers]},
        ).execute()


def _read_app_list(service, spreadsheet_id, tab="App List"):
    rows = _read_tab_values(service, spreadsheet_id, tab, "A2:A")
    apps = []
    seen = set()
    for row in rows:
        if not row:
            continue
        name = " ".join(str(row[0]).split())
        key = name.casefold()
        if name and key not in seen:
            terms = [name]
            underscore_variant = " ".join(name.replace("_", " ").split())
            if underscore_variant != name:
                terms.append(underscore_variant)
            apps.append({"name": name, "terms": terms})
            seen.add(key)
    if not apps:
        raise ValueError(f"No application names found in column A of {tab!r}, row 2 onward")
    return apps


def _read_email_addresses(service, spreadsheet_id, tab="Emails"):
    rows = _read_tab_values(service, spreadsheet_id, tab, "B2:B")
    addresses = []
    for row in rows:
        if not row:
            continue
        address = str(row[0]).strip()
        if not address:
            continue
        if not EMAIL_RE.fullmatch(address):
            raise ValueError(
                f"Invalid email address in column B of {tab!r}: {address!r}"
            )
        if address.casefold() not in {item.casefold() for item in addresses}:
            addresses.append(address)
    if not addresses:
        raise ValueError(f"No email addresses found in column B of {tab!r}, row 2 onward")
    return addresses


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


def _state_key(article, app_list_fingerprint):
    if article.get("content_hash"):
        content_key = f"{article['link']}#content-{article['content_hash']}"
    else:
        content_key = article["link"]
    return f"{content_key}#apps-{app_list_fingerprint}"


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
    return _read_tab_values(service, spreadsheet_id, cve_tab, "A2:H")


def _cve_order(cve):
    match = CVE_RE.fullmatch(str(cve).upper())
    if not match:
        return 1, str(cve).casefold()
    year, number = re.fullmatch(r"CVE-(\d{4})-(\d+)", str(cve).upper()).groups()
    return 0, int(year), int(number)


def _new_alerts(existing, alerts):
    existing_cves = {}
    for row in existing:
        identifier = row[1].strip().upper() if len(row) > 1 else ""
        if CVE_RE.fullmatch(identifier):
            existing_cves.setdefault(identifier, row)

    unique_alerts = {}
    for alert in alerts:
        identifier = alert["identifier"].upper()
        if not CVE_RE.fullmatch(identifier):
            continue
        existing_row = existing_cves.get(identifier)
        if existing_row:
            is_zero_day = len(existing_row) > 6 and existing_row[6].strip().casefold() == "yes"
            critical_email_sent = (
                len(existing_row) > 7 and existing_row[7].strip().casefold() == "yes"
            )
            previous_severity = (
                existing_row[5].strip().casefold() if len(existing_row) > 5 else "unknown"
            )
            current_severity = alert["severity"].casefold()
            if SEVERITY_RANK.get(previous_severity, 0) > SEVERITY_RANK.get(
                current_severity, 0
            ):
                alert = {**alert, "severity": existing_row[5]}
                current_severity = alert["severity"].casefold()
            if (
                is_zero_day
                and SEVERITY_RANK.get(current_severity, 0)
                <= SEVERITY_RANK.get(previous_severity, 0)
                and not (current_severity == "critical" and not critical_email_sent)
            ):
                continue
        current = unique_alerts.get(identifier)
        if current:
            preferred = alert
            if SEVERITY_RANK.get(alert["severity"].casefold(), 0) < SEVERITY_RANK.get(
                current["severity"].casefold(), 0
            ):
                preferred = current
            unique_alerts[identifier] = {
                **preferred,
                "assets": sorted(
                    set(current["assets"]) | set(alert["assets"]),
                    key=str.casefold,
                ),
            }
        else:
            unique_alerts[identifier] = alert
    return list(unique_alerts.values())


def _append_alerts_in_order(service, spreadsheet_id, cve_tab, existing, alerts):
    max_number = max(
        (
            int(str(row[0]).strip())
            for row in existing
            if row and str(row[0]).strip().isdigit()
        ),
        default=0,
    )

    sorted_alerts = sorted(
        _new_alerts(existing, alerts),
        key=lambda alert: _cve_order(alert["identifier"]),
    )
    existing_rows = {
        row[1].strip().upper(): (index + 2, row)
        for index, row in enumerate(existing)
        if len(row) > 1 and CVE_RE.fullmatch(row[1].strip().upper())
    }
    rows = []
    values = service.spreadsheets().values()
    quoted = "'" + cve_tab.replace("'", "''") + "'"
    for alert in sorted_alerts:
        existing_entry = existing_rows.get(alert["identifier"].upper())
        if existing_entry:
            row_number, old_row = existing_entry
            affected = set(
                item.strip()
                for item in (old_row[2].split(";") if len(old_row) > 2 else [])
                if item.strip()
            )
            affected.update(alert["assets"])
            values.update(
                spreadsheetId=spreadsheet_id,
                range=f"{quoted}!C{row_number}:H{row_number}",
                valueInputOption="RAW",
                body={
                    "values": [[
                        "; ".join(sorted(affected, key=str.casefold)),
                        alert["found_at"],
                        alert["link"],
                        alert["severity"],
                        "Yes",
                        "Yes" if alert["severity"].casefold() == "critical" else (
                            old_row[7] if len(old_row) > 7 else ""
                        ),
                    ]]
                },
            ).execute()
            continue
        rows.append(
            [
                max_number + len(rows) + 1,
                alert["identifier"],
                "; ".join(sorted(set(alert["assets"]), key=str.casefold)),
                alert["found_at"],
                alert["link"],
                alert["severity"],
                "Yes",
                "Yes" if alert["severity"].casefold() == "critical" else "",
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

    zero_day_evidence = " ".join(
        str(analysis.get("zero_day_evidence", "")).split()
    )
    article_text = " ".join(f"{title} {text}".split())
    zero_day_value = analysis.get("zero_day")
    zero_day_flag = zero_day_value is True or (
        isinstance(zero_day_value, str)
        and zero_day_value.strip().casefold() == "true"
    )
    if (
        not zero_day_flag
        or not zero_day_evidence
        or not ZERO_DAY_RE.search(zero_day_evidence)
        or zero_day_evidence.casefold() not in article_text.casefold()
    ):
        return [], provider, "not a confirmed zero-day"

    analyzed_products = cyberintel._string_list(analysis.get("affected_products"))
    evidence = " ".join(
        (
            text,
            title,
            cyberintel._string_list(analysis.get("summary")),
            analyzed_products,
        )
    )
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
    severity = str(analysis.get("severity", "Unknown")).strip().title()
    if severity not in {
        "Informational",
        "Low",
        "Medium",
        "High",
        "Critical",
        "Unknown",
    }:
        severity = "Unknown"
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
                    "severity": severity,
                }
            )

    if failed_lookup:
        raise RuntimeError("One or more CVE lookups failed; article will be retried")
    status = "matched zero-day CVE" if alerts else "no tracked asset match"
    return alerts, provider, status


def _send_messages(recipients, subject, body):
    host = os.getenv("EMAIL_SMTP_HOST", "smtp.gmail.com")
    try:
        port = int(os.getenv("EMAIL_SMTP_PORT", "587"))
    except ValueError as error:
        raise ValueError("EMAIL_SMTP_PORT must be an integer") from error
    username = os.getenv("EMAIL_SMTP_USERNAME", "").strip()
    password = os.getenv("EMAIL_SMTP_PASSWORD", "")
    sender = os.getenv("EMAIL_FROM", "").strip() or username
    if not username or not password or not sender:
        raise ValueError(
            "Set EMAIL_SMTP_USERNAME and EMAIL_SMTP_PASSWORD secrets before enabling email"
        )

    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=30) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(username, password)
        for recipient in recipients:
            message = EmailMessage()
            message["From"] = sender
            message["To"] = recipient
            message["Subject"] = subject
            message.set_content(body)
            refused = server.send_message(message)
            if recipient in refused:
                raise RuntimeError(f"SMTP server refused recipient {recipient!r}")


def _format_alert_timestamp(value):
    local_time = value.astimezone(PACIFIC)
    date_text = local_time.strftime("%m/%d/%y")
    time_text = local_time.strftime("%I:%M %p").lstrip("0")
    time_text = time_text.replace("AM", "A.M").replace("PM", "P.M")
    return f"{date_text} {time_text}"


def _send_critical_alerts(service, spreadsheet_id, alerts, emails_tab):
    critical_alerts = [
        alert for alert in alerts if alert.get("severity", "").casefold() == "critical"
    ]
    if not critical_alerts:
        return 0
    recipients = _read_email_addresses(service, spreadsheet_id, emails_tab)
    for alert in critical_alerts:
        subject = (
            "Critical Zero Day Vulnerability Found "
            f"({_format_alert_timestamp(datetime.now(PACIFIC))})"
        )
        affected = "; ".join(sorted(set(alert["assets"]), key=str.casefold))
        body = (
            "Critical vulnerabilities found that affect apps from the app list.\n\n"
            f"Vulnerability discovered affecting {affected}\n"
            f"CVE: {alert['identifier']}\n"
            f"Affected Software/Hardware: {affected}\n"
            f"Link: {alert['link']}\n"
        )
        _send_messages(recipients, subject, body)
    return len(critical_alerts)


def _date_found_in_pacific(value):
    try:
        found = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if found.tzinfo is None:
        found = found.replace(tzinfo=timezone.utc)
    return found.astimezone(PACIFIC).date()


def run_daily_report(
    spreadsheet_id,
    credentials_path,
    cve_tab="CVEs",
    emails_tab="Emails",
    now=None,
):
    service = cyberintel._sheet_service(credentials_path)
    recipients = _read_email_addresses(service, spreadsheet_id, emails_tab)
    local_now = now or datetime.now(PACIFIC)
    if local_now.tzinfo is None:
        local_now = local_now.replace(tzinfo=PACIFIC)
    yesterday = local_now.astimezone(PACIFIC).date() - timedelta(days=1)
    rows = _read_tab_values(service, spreadsheet_id, cve_tab, "A2:H")
    findings = []
    seen_cves = set()
    for row in rows:
        if len(row) < 7 or row[6].strip().casefold() != "yes":
            continue
        if _date_found_in_pacific(row[3] if len(row) > 3 else "") != yesterday:
            continue
        cve = row[1].strip() if len(row) > 1 else ""
        if not CVE_RE.fullmatch(cve) or cve.upper() in seen_cves:
            continue
        seen_cves.add(cve.upper())
        affected = row[2].strip() if len(row) > 2 else "Unknown"
        link = row[4].strip() if len(row) > 4 else ""
        findings.append((cve, affected or "Unknown", link, row[5] if len(row) > 5 else "Unknown"))

    findings.sort(key=lambda finding: _cve_order(finding[0]))
    subject = f"Report for {yesterday.strftime('%m/%d/%y')}"
    if findings:
        sections = []
        for cve, affected, link, severity in findings:
            sections.append(
                f"Vulnerability discovered affecting {affected}\n"
                f"CVE: {cve}\n"
                f"Affected Software/Hardware: {affected}\n"
                f"Severity: {severity}\n"
                f"Link: {link}"
            )
        body = "\n\n".join(sections)
    else:
        body = f"No tracked zero-day vulnerabilities were found on {yesterday:%m/%d/%y}."
    _send_messages(recipients, subject, body)
    LOG.info(
        "Daily report for %s sent to %d recipient(s) with %d finding(s)",
        yesterday,
        len(recipients),
        len(findings),
    )
    return len(findings)


def run_monitor(
    spreadsheet_id,
    credentials_path,
    links_tab="Links",
    cve_tab="CVEs",
    state_tab="ScanState",
    app_list_tab="App List",
    emails_tab="Emails",
    max_articles=5,
):
    if max_articles < 1:
        raise ValueError("max_articles must be greater than zero")
    service = cyberintel._sheet_service(credentials_path)
    assets = _read_app_list(service, spreadsheet_id, app_list_tab)
    app_list_fingerprint = hashlib.sha256(
        json.dumps(assets, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
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
            key = _state_key(article, app_list_fingerprint)
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
        key = _state_key(article, app_list_fingerprint)
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

    new_alerts = _new_alerts(existing_cves, alerts)
    _send_critical_alerts(service, spreadsheet_id, new_alerts, emails_tab)
    _append_alerts_in_order(service, spreadsheet_id, cve_tab, existing_cves, new_alerts)
    _append_rows(service, spreadsheet_id, state_tab, STATE_HEADERS, state_rows)
    LOG.info(
        "Zero-day scan complete: %d new article(s) analyzed, %d tracked CVE(s) found, "
        "%d article(s) failed",
        processed,
        len(new_alerts),
        failures,
    )
    return failures
