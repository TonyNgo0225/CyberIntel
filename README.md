# CyberIntel

A local Python 3.10+ script that collects CVE mentions from public RSS/Atom feeds,
enriches them using the CVE Program API, and optionally appends them to an existing
Google Sheet. No server, AI key, or paid service is required. Provider quotas apply.

## Try it without Google credentials

```sh
python cyberintel.py --max-articles 5
```

The default is a dry run: it writes `output/vulnerabilities.csv` and never accesses
Google Sheets. Each run replaces this CSV; it is a preview, not a persistent log.
The collector itself uses only Python's standard library.

Edit `sources.json` to choose HTTPS RSS/Atom feeds. Each entry has a `name` and
`url`. By default only feed text is scanned. To also look for CVEs in article HTML:

```sh
python cyberintel.py --max-articles 5 --fetch-articles
```

Check website terms before enabling article fetching. HTML scanning can include
related-story links, and JavaScript-only or blocked pages may not work. CVE mentions
are leads for review, not proof that the article describes an affected product.

## Connect your existing Google Sheet

1. Create/select a Google Cloud project and enable the **Google Sheets API**.
   This workflow does not require a paid AI service or a hosted server.
2. Create a service account and download a JSON key. Keep it outside the repository;
   never commit or share it. Your Google organization may restrict key creation.
3. Share only the target spreadsheet with the service account's email as **Editor**.
4. Create an empty tab named `Vulnerabilities`, or use `--tab` to choose another tab.
   For an existing populated tab, A1:E1 must exactly match:

   `Article link`, `CVE`, `Products affected`, `CVE published date`, `Added at`

   Use a dedicated tab if your existing columns differ. The script refuses mismatched
   headers rather than altering existing data. It does not create missing tabs.
5. Install the optional Google dependencies:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

Run with your spreadsheet ID (the part between `/d/` and `/edit` in its URL):

```sh
python cyberintel.py --write-sheet \
  --spreadsheet-id YOUR_SPREADSHEET_ID \
  --credentials /path/outside/repo/service-account.json
```

Alternatively set `CYBERINTEL_SPREADSHEET_ID` and `GOOGLE_APPLICATION_CREDENTIALS`
in your local shell. Never put credential contents into command arguments or source.

## Data and reruns

- One row per article URL + CVE ID. Existing sheet rows are read before appending;
  the same CVE in a different article gets its own row.
- Dates come from the official CVE record's publication timestamp. `Added at` is
  the collection timestamp in UTC. It is separate from the article publication date.
- Products are the vendor/product labels supplied by the CNA in the CVE record.
  They are not a complete version exposure assessment. Missing fields say `Unknown`;
  rejected records are explicitly labeled.
- Failed lookups are logged and skipped so they can be retried on a later run.
  Existing rows are not refreshed automatically when CVE records change.
- Feed windows are finite: this is recent-news collection, not historical backfill.
- Do not run concurrent writers: deduplication is not an atomic transaction. If an
  append has an uncertain network outcome, rerun to reread the sheet before retrying.
- Exit code 0 means processing completed; 1 means an error or partial result. A
  successful run may find zero CVEs. Check the logs and CSV rather than assuming
  every feed article contains vulnerabilities.
- CSV output escapes formula-like values; sheet writes use `RAW` values.

No scheduling is installed. Run manually while testing. AI extraction, email feeds,
accounts, and a web UI are deliberately outside this first version.

## Tests

```sh
python -m unittest discover -s tests -v
```

Tests use fixtures and mocks; they do not access your sheet. A live dry run requires
access to your source hosts and `cveawg.mitre.org`. Google writes additionally require
Google API access and your own service account credentials.
