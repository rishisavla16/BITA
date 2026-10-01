# BITA: Browser Isolation and Threat Analyzer

BITA is a local Flask web application for inspecting untrusted URLs in a server-side, headless Chromium browser. It does not load the submitted site directly in the analyst's browser. Instead, it returns a controlled screenshot, page metadata, redirect information, observed DOM metrics, heuristic reasons, and a risk score.

> **Important:** BITA is an analysis and triage aid, not a malware sandbox, antivirus product, allowlist authority, or replacement for professional security review. The result can contain false positives and false negatives. Never submit secrets or rely on a single report for a security decision.

## Features

- Accepts a URL with or without an explicit `http://` or `https://` scheme.
- Rejects malformed URLs, unsupported schemes, oversized input, and obvious localhost targets.
- Opens the target only in a Playwright-controlled headless Chromium context.
- Disables browser downloads and uses a fixed 1440 x 900 viewport.
- Captures a live preview while an asynchronous analysis is running.
- Captures a final full-page screenshot after the page settles.
- Records the final URL, page title, HTTP status, redirect chain, and selected page metrics.
- Detects signals such as credential forms, authentication-like forms, suspicious keywords, raw IP hosts, long URLs, external scripts, and missing HTTPS.
- Checks the final host against a configurable safe-domain source using a cached Bloom filter.
- Produces a score from 0 to 100 and one of these verdicts: `Safe`, `Low to Moderate`, `Suspicious`, or `High Risk`.
- Stores completed asynchronous analyses in a local SQLite database.
- Lets an analyst copy a text report or open a print dialog to save a PDF report.

## How It Works

```text
Analyst browser
      |
      | POST /analyze/start
      v
Flask application
      |
      | background thread
      v
Playwright + isolated Chromium context
      |
      | screenshot, redirects, title, status, DOM metrics
      v
Behavior analysis -> risk scoring -> SQLite log
      |
      v
Frontend polls /analyze/status/<job_id> and renders the report
```

The application never sends the target page's raw HTML to the frontend. The browser client receives derived metadata and screenshots served from the application's controlled `screenshots/` directory.

## Requirements

- Windows, macOS, or Linux.
- Python 3.10 or newer is recommended because the code uses modern type-union syntax such as `str | None`.
- A Chromium browser installed by Playwright.
- Network access from the machine running BITA to the URLs being analyzed and, on first setup, to install Python packages and the Playwright browser.

Runtime dependencies are listed in [`requirements.txt`](requirements.txt):

- Flask 3 or newer
- Playwright 1.40 or newer

## Installation

Open a terminal in this directory:

```powershell
cd C:\Users\rishi\Desktop\BITA\rbi-threat-analyzer
```

Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, either enable the current-user script policy or activate from Command Prompt instead:

```cmd
.venv\Scripts\activate.bat
```

Install Python dependencies and the Playwright browser:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
```

The browser installation is required. Installing only the Python package is not enough for `run_in_sandbox()` to launch Chromium.

## Running the Application

Start the development server with:

```powershell
python app.py
```

The server binds to `127.0.0.1:5000` with debug mode disabled. Open:

```text
http://127.0.0.1:5000/
```

To stop the server, press `Ctrl+C`.

The application creates these generated files or directories when needed:

- `analysis_logs.db`: SQLite analysis history. It is ignored by Git.
- `screenshots/`: final screenshots and short-lived live previews. It is ignored by Git.
- `intel/safe_domains_10m.bloom`: cached Bloom-filter bit array.
- `intel/safe_domains_10m.meta.json`: cache metadata. It is ignored by Git.

## Using the Web Interface

1. Enter a URL such as `https://example.com`.
2. Select **Analyze**.
3. Watch the live sandbox stage and preview while the job runs.
4. Review the verdict, score, reasons, metadata, signal breakdown, redirect chain, and final screenshot.
5. Use **Copy Report** to copy a plain-text report or **Download PDF** to open a browser print dialog.

The **Cancel** button stops frontend polling and marks the UI as cancelled. It does not terminate a browser already running on the server; the background job may continue until it completes or fails. Completed job records are retained in memory for approximately 30 minutes.

## HTTP API

### `GET /`

Returns the HTML application.

### `POST /analyze`

Runs a complete analysis synchronously. This route is useful for API clients that can wait for the browser operation to finish. It does not expose a live preview.

Request:

```json
{
  "url": "https://example.com"
}
```

Successful response fields include:

```json
{
  "ok": true,
  "submitted_url": "https://example.com",
  "normalized_url": "https://example.com",
  "final_url": "https://example.com/",
  "title": "Example Domain",
  "status_code": 200,
  "screenshot_path": "/screenshots/capture_<uuid>.png",
  "redirect_chain": ["https://example.com/"],
  "redirect_count": 0,
  "reasons": [],
  "signals": {},
  "safe_match": {
    "matched": false,
    "source": "bloom",
    "host": "example.com"
  },
  "risk_score": 2,
  "verdict": "Low to Moderate"
}
```

The `signals` object contains the detailed boolean and numeric metrics described in the Detection and Scoring section. Possible error responses include `400` for invalid input, `502` for a sandbox timeout or Playwright failure, and `500` for an unexpected server-side failure. Internal exception details are not returned to the client.

### `POST /analyze/start`

Starts an asynchronous analysis and returns immediately:

```json
{
  "ok": true,
  "job_id": "<uuid without hyphens>"
}
```

The frontend uses this route.

### `GET /analyze/status/<job_id>`

Returns the current job state:

```json
{
  "ok": true,
  "job_id": "<job id>",
  "status": "running",
  "stage": "Initial page render captured",
  "preview_path": "/screenshots/job_<id>_live_<uuid>.png",
  "error": ""
}
```

The `status` value is normally `queued`, `running`, `completed`, or `failed`. A completed response also includes `result`, using the same result fields as `POST /analyze`. Unknown or expired jobs return `404`.

### `GET /screenshots/<filename>`

Serves a generated screenshot from the controlled screenshots directory. Filenames are generated by the server. Old files are periodically deleted after approximately 30 minutes.

## URL Validation

`normalize_url()` applies these rules before a browser is started:

- Leading and trailing whitespace is removed.
- A missing scheme defaults to `https://`.
- Only `http` and `https` are accepted.
- A network location/host is required.
- URLs longer than 2048 characters are rejected.
- `localhost`, `127.0.0.1`, `0.0.0.0`, and `::1` are rejected as obvious local targets.

This is input validation, not a complete server-side request isolation policy. The browser process still needs appropriate OS, container, network, and egress controls in any deployment that handles hostile URLs.

## Sandbox Behavior

The sandbox implementation is in [`analyzer/sandbox.py`](analyzer/sandbox.py). For every analysis it:

1. Launches headless Chromium.
2. Creates a new browser context with downloads disabled.
3. Enables JavaScript because many real pages require it to render.
4. Ignores HTTPS certificate errors so certificate problems can be observed instead of preventing all analysis.
5. Uses a 10-second default navigation and page timeout.
6. Tracks main-frame navigation events to build a redirect chain.
7. Captures an initial viewport screenshot for the live preview.
8. Waits 1.2 seconds for additional page activity.
9. Captures a full-page final screenshot.
10. Evaluates a small script to count forms, password inputs, email inputs, authentication hints, external scripts, and the first 50,000 characters of visible body text.

The captured text excerpt is used only for keyword detection and is not returned in the final API result.

## Detection and Scoring

### Behavior signals

The behavior analyzer in [`analyzer/behavior.py`](analyzer/behavior.py) adds reasons for:

- Two or more redirects.
- A password input.
- An authentication-like form containing account, login, verify, or password hints plus an email or password input.
- The keywords `login`, `verify`, `bank`, `password`, or `secure` in the page title or visible text excerpt.
- Twelve or more external scripts.
- A final URL whose host is a raw IPv4 address.
- A final URL at least 140 characters long.
- A final URL that is not HTTPS.

### Score weights

The scorer in [`analyzer/scorer.py`](analyzer/scorer.py) starts at `2` and applies these additions:

| Signal | Score change |
| --- | ---: |
| Two or more redirects | +12 |
| Four or more redirects | +8 additional |
| Credential form with password input | +26 |
| Authentication-like form without a password input | +10 |
| Any other form | +1 |
| Suspicious keywords | +3 per keyword, capped at +12 |
| 25 or more external scripts | +8 |
| 50 or more external scripts | +10 additional |
| Raw IP host | +24 |
| URL length of at least 140 characters | +10 |
| Non-HTTPS final URL | +8 |
| Safe-index match | -18 |

The score is clamped to `0..100`. A safe-index match can clamp a result to at most `8` when there are no major flags. Major flags are a raw IP, a credential form, four or more redirects, or non-HTTPS. Verdict thresholds are:

| Score/result | Verdict |
| --- | --- |
| Safe-index match, no major flags, score below 20 | `Safe` |
| 75 or higher | `High Risk` |
| 45 to 74 | `Suspicious` |
| Below 45 | `Low to Moderate` |

The safe index changes the score, but it does not override major suspicious behavior.

## Safe-Domain Intelligence

The default source is [`intel/safe_domains_10m.txt`](intel/safe_domains_10m.txt). It accepts one domain or URL per line, for example:

```text
google.com
youtube.com
https://microsoft.com
```

Hosts are normalized to lowercase, surrounding dots are removed, and a leading `www.` is removed. The application loads or builds these cache files at startup:

- `intel/safe_domains_10m.bloom`
- `intel/safe_domains_10m.meta.json`

The cache is reused only when the source path and source modification time match. If either cache is missing or stale, the source is scanned and a new filter is built. Membership checks are average O(1), but Bloom filters can produce false positives. A match means “possibly present in the source,” not verified trustworthiness.

Override the default paths with environment variables:

```powershell
$env:SAFE_URL_SOURCE_FILE = "D:\intel\trusted-domains.txt"
$env:SAFE_URL_BLOOM_FILE = "D:\intel\trusted-domains.bloom"
$env:SAFE_URL_META_FILE = "D:\intel\trusted-domains.meta.json"
python app.py
```

If the source file is absent, the application starts without a ready index and all safe-index matches are false.

## Persistence and Retention

Completed asynchronous jobs are held in process memory and pruned after 1800 seconds. Screenshot cleanup runs at most every 300 seconds and removes screenshot files older than 1800 seconds. The synchronous route removes its temporary live preview immediately.

Completed asynchronous results are written to `analysis_logs.db` with:

- Submitted URL
- Normalized URL
- Final URL
- Page title
- Risk score
- Verdict
- Reasons joined into a text field
- UTC creation timestamp

The database has no built-in authentication, encryption, web history UI, or automatic row-retention policy. Treat it as local sensitive analysis data and protect the host filesystem.

## Project Layout

```text
rbi-threat-analyzer/
|-- app.py                         Flask application, routes, jobs, and SQLite logging
|-- requirements.txt               Python dependencies
|-- analyzer/
|   |-- behavior.py                Observed behavior signals and explanatory reasons
|   |-- safe_lookup.py             Host normalization and Bloom-filter index
|   |-- sandbox.py                 Playwright isolated-browser execution
|   `-- scorer.py                  Risk score and verdict calculation
|-- intel/
|   |-- README.md                  Safe-index file format notes
|   |-- safe_domains_10m.txt      Source host/domain list
|   |-- safe_domains_10m.bloom    Generated Bloom-filter cache
|   `-- safe_domains_10m.meta.json Generated cache metadata
|-- templates/
|   `-- index.html                 Main web interface
|-- static/
|   |-- script.js                  Submission, polling, rendering, copy, and PDF logic
|   `-- style.css                  Interface styling and responsive layout
|-- screenshots/                   Generated screenshots, ignored by Git
|-- analysis_logs.db               Generated SQLite database, ignored by Git
`-- README.md
```

## Development Checks

There is currently no automated test suite or lint configuration in the repository. Before committing a Python change, run a syntax check:

```powershell
python -m compileall app.py analyzer
```

Then perform a manual smoke test:

1. Start the server with `python app.py`.
2. Open `http://127.0.0.1:5000/`.
3. Analyze a benign URL that you control or are authorized to inspect.
4. Confirm the live preview, final screenshot, score, signal breakdown, and report actions work.
5. Check that `analysis_logs.db` receives a completed asynchronous entry.

For a direct API smoke test from PowerShell:

```powershell
$body = @{ url = "https://example.com" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:5000/analyze" -Method Post -ContentType "application/json" -Body $body
```

## Troubleshooting

### `Executable doesn't exist` or Chromium launch failure

Install the browser binaries:

```powershell
python -m playwright install chromium
```

### The page is unreachable or times out

The target may be offline, blocked by the host network, dependent on a slow resource, or intentionally non-responsive. The sandbox timeout is currently 10 seconds.

### Safe-index match is always false

Confirm that `intel/safe_domains_10m.txt` exists and contains valid domains. If using overrides, verify all three environment variables point to the intended files. Delete stale generated cache files if you need to force a rebuild; the application will rebuild them at startup.

### The live preview is blank or unavailable

The preview is generated after the initial DOM content load and is temporary. A failed navigation, timeout, expired job, or early cancellation can prevent it from being shown.

### Jobs disappear

In-memory jobs are intentionally temporary and are pruned after approximately 30 minutes. Restarting the Flask process also clears them. Completed result fields are logged separately in SQLite.

### PowerShell cannot activate the virtual environment

Use Command Prompt activation (`.venv\Scripts\activate.bat`) or run the virtual-environment interpreter directly, for example `.venv\Scripts\python.exe app.py`.

## Security and Deployment Notes

- Keep BITA bound to localhost unless you add authentication, authorization, rate limiting, CSRF protections, request logging, and a carefully designed public deployment boundary.
- Run hostile browsing in a dedicated low-privilege environment or container with restricted filesystem access and controlled outbound networking.
- Do not expose the screenshot directory or SQLite database through a general file server.
- Consider browser hardening, resource limits, DNS/IP egress controls, process isolation, and a separate worker service before handling untrusted users at scale.
- `ignore_https_errors=True` is intentional for observation but should be treated as a risk when interpreting results.
- The current localhost blocklist is only an obvious-target check and does not cover every private, link-local, encoded, redirected, or DNS-rebinding address.
- The app has no authentication or multi-user isolation.
- Do not treat a `Safe` verdict as proof that a site is safe, current, uncompromised, or affiliated with a legitimate organization.

## License and Ownership

No license file is currently included in the repository. The UI credits report analysis to BITA and development to Rishi Savla. Add an explicit license before distributing the project or accepting external contributions.
