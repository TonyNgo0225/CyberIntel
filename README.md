# CyberIntel

CyberIntel collects cybersecurity stories from RSS/Atom feeds, uses Google AI
Studio to analyze article pages, and falls back to Groq if Google AI Studio is
unavailable. Results can be previewed as CSV or appended to Google Sheets. A
separate CVE collection mode is also available.

## Configure AI providers

Create an API key in Google AI Studio and, as a backup, a Groq API key. Set the
keys in your local shell; do not put them in source files or commit them:

```powershell
$env:GOOGLE_AI_STUDIO_API_KEY = "your-google-ai-studio-key"
$env:GROQ_API_KEY = "your-groq-key"
```

Google AI Studio is tried first. Groq is used if Google AI Studio fails or its key
is not set. The defaults are `gemini-2.5-flash` and
`llama-3.3-70b-versatile`; override them with `GEMINI_MODEL` and `GROQ_MODEL` if
needed.

Edit `sources.json` to add or remove HTTPS RSS/Atom feeds. Two cybersecurity news
feeds are included as starting sources. The article scanner fetches each feed and
its linked article page, then sends the text to the configured AI provider for a
headline, date, concise summary, topics, threats, CVEs, severity, and recommended
action. Article text is untrusted input and should be checked before acting on
generated recommendations. Respect each publisher's terms and access policies.

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

Newsletter analyses go to the `Articles` tab by default. The script creates the
header row in an empty tab, or requires an existing header to match exactly:

`Article link`, `Source`, `Headline`, `Published date`, `Summary`, `Topics`,
`Threats`, `CVEs`, `Severity`, `Recommended action`, `AI provider`, `Added at`

Use `--tab "Your tab name"` to choose a different tab. Existing article links are
not appended again. Only explicit `--write-sheet` runs access or modify Sheets.
Use `--spreadsheet-id` and `--credentials` to override the environment variables.

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
