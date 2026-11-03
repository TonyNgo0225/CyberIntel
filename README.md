# CyberIntel

CyberIntel collects cybersecurity stories from RSS/Atom feeds, uses Google AI
Studio to analyze article pages, and falls back to Groq if Google AI Studio is
unavailable. Results can be previewed as CSV or appended to Google Sheets. A
separate CVE collection mode is also available.

## Configure keys and Google Sheets

First enable the Google Sheets API, create a service account, and download its
JSON key outside the repository. On Windows, run the interactive setup script
from the repository folder:

```powershell
.\setup.ps1
```

It prompts for the Google AI Studio and optional Groq keys (input is hidden), the
spreadsheet ID, and the path to the Google service-account JSON key. It also asks
for the result tab names and model names, then saves the settings to a local
`.env` file. The collector loads that file automatically; shell environment
variables take precedence. The setup script checks the service-account file and
shows its email so you can share the spreadsheet with it as an Editor.

The `.env` file contains API keys in plain text. It is excluded by `.gitignore`,
but keep it private and do not upload or commit it. Keep the service-account key
JSON outside the repository. Re-running setup prompts before replacing an
existing `.env`.

You can also set the configuration manually in your shell or `.env` file:

Create an API key in Google AI Studio and, as a backup, a Groq API key. Set the
keys in your local shell; do not put them in source files or commit them:

```powershell
$env:GOOGLE_AI_STUDIO_API_KEY = "your-google-ai-studio-key"
$env:GROQ_API_KEY = "your-groq-key"
```

Google AI Studio is tried first. Groq is used if Google AI Studio fails or its key
is not set. The defaults are `gemini-3.6-flash` and `openai/gpt-oss-120b`;
override them with `GEMINI_MODEL` and `GROQ_MODEL` if needed.

Edit `sources.json` to add or remove HTTPS RSS/Atom feeds. Two cybersecurity news
feeds are included as starting sources. The article scanner fetches each feed and
its linked article page, then sends the text to the configured AI provider for a
headline, date, concise summary, topics, threats, CVEs, severity, and recommended
action. Article text is untrusted input and should be checked before acting on
generated recommendations. Respect each publisher's terms and access policies.

## Hourly inventory monitoring with GitHub Actions

The hourly workflow is `.github/workflows/hourly-cyberintel.yml`. It reads HTTPS
source URLs from the existing `Links` sheet tab, follows supported RSS feeds,
checks up to five recent entries per feed per run, and writes only new findings
that match your tracked assets to the existing `CVEs` tab. It runs at the top of
each hour (UTC); GitHub may delay scheduled starts during busy periods. You can
also run it manually from the repository's **Actions** tab.

The scanner recognizes the news feeds for CyberPress, Cybersecurity News, The
Hacker News, DataBreachToday, Dark Reading, BleepingComputer, The Register,
Infosecurity Magazine, and Cybersecurity Dive. It can also inspect the specific
Dark Reading article and the Tenable Plugins page listed in `Links`. Armis's CVE
list is loaded dynamically and has no verified public feed, while Shodan is a
search/API platform rather than a news feed; those two links are skipped with a
warning. A future Shodan integration would need its API and explicitly scoped
assets or network ranges.

### Configure the tracked assets

Keep the inventory private: this GitHub repository is public, so do not put your
organization's software/hardware list in a tracked file. Add a repository Actions
secret named `CYBERINTEL_INVENTORY_JSON` containing JSON in this shape:

```json
{
  "assets": [
    {
      "name": "Example product name",
      "vendor": "Example vendor",
      "aliases": ["Exact product name", "Common product abbreviation"]
    }
  ]
}
```

Use the real product and hardware names your organization runs, including
version/product aliases that vendors use in vulnerability advisories. The
scanner requires at least one asset and uses whole-name matching to reduce
incidental matches. `inventory.example.json` is a public template; a local
`inventory.json` is Git-ignored.

### Add repository secrets

In the public repository, open **Settings → Secrets and variables → Actions →
New repository secret**, then add:

| Secret name | Value |
| --- | --- |
| `CYBERINTEL_INVENTORY_JSON` | Your private asset inventory JSON |
| `CYBERINTEL_SPREADSHEET_ID` | ID from the Google Sheet URL |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | Entire service-account JSON key file contents |
| `GOOGLE_AI_STUDIO_API_KEY` | Google AI Studio API key |
| `GROQ_API_KEY` | Groq API key (optional fallback) |

The service-account email must have **Editor** access to the spreadsheet. Secrets
are injected at run time; the credential JSON is written only to the GitHub
runner's temporary directory. Do not commit credentials, API keys, or the real
asset inventory. Standard GitHub-hosted Actions runners are free for public
repositories.

After adding the workflow and secrets to the default branch, run it once
manually from **Actions → Hourly CyberIntel inventory scan → Run workflow**.
It creates a `ScanState` tab to avoid re-analyzing already processed articles.
Changing the inventory causes recent feed items to be checked again against the
updated asset list.
It only appends rows to the existing `CVEs` tab when its headers exactly match:

`Number`, `CVE`, `Affected Software/Hardware`, `Date/Time Found`, `Link`

Numbers continue from the highest existing number; new CVEs in each run are
ordered by year and numeric CVE ID. Existing CVEs are not appended twice.
Confirmed inventory-matched CVEs are logged regardless of severity. Malware
without a CVE is logged only when the AI classifies it as High/Critical and it
matches a tracked asset; its CVE cell says `MALWARE (no CVE)`.

For local testing, copy `inventory.example.json` to the ignored `inventory.json`,
edit its assets, and run:

```powershell
python cyberintel.py --monitor-inventory --write-sheet --max-articles 5
```

## Preview an AI newsletter scan

Install the optional Google Sheets dependencies only if you plan to write to a
sheet:

```powershell
python -m pip install -r requirements.txt
```

Run a local preview; no Google credentials are required:

```powershell
python cyberintel.py --scan-newsletters --max-articles 5 --output output/articles.csv
```

The article CSV has one row per analyzed article. This preview does not require
Google Sheets credentials, but it does require at least one AI-provider API key.
Failed feeds, article fetches, and AI analyses are logged; the process returns a
nonzero exit code if any part of the scan fails.

## Write AI results to Google Sheets

1. Enable the **Google Sheets API** in a Google Cloud project.
2. Create a service account and download its JSON key outside this repository.
   Never commit or share the key.
3. Share the target spreadsheet with the service account email as **Editor**.
4. Set the spreadsheet ID and service-account file path in PowerShell:

```powershell
$env:CYBERINTEL_SPREADSHEET_ID = "your-spreadsheet-id"
$env:GOOGLE_APPLICATION_CREDENTIALS = "C:\path\outside\repo\service-account.json"
```

5. Run the scan with the explicit write option:

```powershell
python cyberintel.py --scan-newsletters --write-sheet --max-articles 5
```

The script creates the header row in an empty tab, or requires an existing
header to match exactly:

`Article link`, `Source`, `Headline`, `Published date`, `Summary`, `Topics`,
`Threats`, `CVEs`, `Severity`, `Recommended action`, `AI provider`, `Added at`

The setup script lets you choose both result tab names. Otherwise, newsletter
analyses go to `Articles` and CVE results go to `CVEs`. Use
`--tab "Your tab name"` to override the configured name for one run. Existing
article links are not appended again. Only explicit `--write-sheet` runs access
or modify Sheets. Use `--spreadsheet-id` and `--credentials` to override the
saved settings.

## CVE collection

The original CVE mode remains available. It scans feed text for CVE IDs, looks up
their official CVE records, and writes `output/vulnerabilities.csv` by default:

```powershell
python cyberintel.py --max-articles 5
```

Use `--fetch-articles` to include article-page text in CVE detection. To append
these rows to a separate `Vulnerabilities` sheet tab:

```powershell
python cyberintel.py --write-sheet --max-articles 5
```

For a populated CVE tab, row 1 must exactly match:

`Article link`, `CVE`, `Products affected`, `CVE published date`, `Added at`

Rows are deduplicated by article URL + CVE ID. CVE publication dates come from
the official CVE record; `Added at` is the UTC collection timestamp. CSV output
escapes formula-like values, and Sheets writes use `RAW`.

## Tests

```powershell
python -m unittest discover -s tests -v
```

Tests use fixtures and mocks. They do not call AI providers, fetch live feeds, or
access Google Sheets.
