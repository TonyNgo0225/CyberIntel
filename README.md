# CyberIntel

CyberIntel scans the cybersecurity sources listed in the Google Sheet's `Links`
tab for articles that explicitly report zero-day vulnerabilities affecting apps
in the sheet's `App List` tab. It records matched CVEs in the `CVEs` tab and can
send email alerts and reports through Gmail SMTP. Malware-only articles are not
recorded.

## Google Sheets layout

- `App List`: application names in column A; row 1 is a heading and is skipped.
- `Emails`: recipient email addresses in column B; row 1 is a heading and is
  skipped. Other columns are ignored.
- `Links`: HTTPS news and vulnerability-source URLs.
- `CVEs`: existing columns `Number`, `CVE`, `Affected Software/Hardware`,
  `Date/Time Found`, and `Link`. The scanner adds `Severity` and `Zero Day`
  columns F and G, plus `Critical Email Sent` in H, to support critical alerts
  and daily reports.
- `ScanState`: created by the scanner to avoid reprocessing unchanged articles.

Add specific product names and variants to `App List` as they appear in vendor
advisories. A CVE is recorded only when the AI identifies an explicit zero-day
claim with a matching quote in the source article and the CVE record matches an
application in the list. Critical alerts are sent once per new matching CVE
identified as Critical. The daily email includes all matching zero-day CVEs
found during the previous calendar day in Pacific time, including noncritical
ones.

## GitHub Actions setup

The repository contains two workflows:

- **Hourly zero-day vulnerability scan** analyzes up to five recent articles
  from each supported source, appends new matching zero-day CVEs, and emails
  each Critical CVE to the addresses in `Emails!B2:B`.
- **Daily zero-day vulnerability report** emails the previous Pacific day's
  matching zero-day findings at 8:00 A.M. Pacific time. It checks at both
  corresponding UTC hours so the send time remains 8:00 A.M. across daylight
  saving changes. You can also run it manually from the Actions tab.

In the repository's **Settings → Secrets and variables → Actions**, create:

| Secret | Value |
| --- | --- |
| `CYBERINTEL_SPREADSHEET_ID` | ID from the Google Sheet URL |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | Full service-account JSON key contents |
| `GOOGLE_AI_STUDIO_API_KEY` | Google AI Studio API key |
| `GROQ_API_KEY` | Optional backup-provider key |
| `EMAIL_SMTP_USERNAME` | Gmail account used to send the email |
| `EMAIL_SMTP_PASSWORD` | Gmail App Password for that account |

The service-account email needs **Editor** access to the spreadsheet. Gmail
SMTP uses `smtp.gmail.com:587`; create a Google App Password for the sending
account and do not use its regular account password. Email addresses are read
from the sheet, not from repository secrets. Keep all credentials in Actions
secrets; do not commit them.

After pushing the workflows to the default branch and adding the secrets, open
**Actions** and run **Hourly zero-day vulnerability scan** to test the setup.
Review the run logs and the `CVEs` tab. The hourly workflow is also available
from **Actions → Hourly zero-day vulnerability scan → Run workflow**.

The workflows use the URLs in `Links`. Armis' supplied CVE page is
JavaScript-loaded and Shodan's homepage is a search/API platform, so those links
are currently skipped rather than treated as news feeds.

## Local use

Install dependencies with `python -m pip install -r requirements.txt`, then
configure the Google Sheets ID, service-account credentials, and AI provider
keys in `.env` or the shell environment. To run the scanner locally:

```powershell
python cyberintel.py --monitor-app-list --write-sheet --max-articles 5
```

To send the previous day's report manually:

```powershell
python cyberintel.py --daily-report
```

Set `EMAIL_SMTP_USERNAME` and `EMAIL_SMTP_PASSWORD` in the environment for local
email delivery. The sender defaults to the SMTP username.
