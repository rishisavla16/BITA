# BITA: Browser Isolation and Threat Analyzer

BITA is a Flask web application for inspecting untrusted URLs inside a **remote, server-side isolated browser**. It does not load the submitted site in the analyst's own browser. Instead, it returns a safe screenshot, page metadata, redirect chain, heuristic reasons, and a risk score.

> **Important:** BITA is an analysis and triage aid, not a malware sandbox, antivirus product, allowlist authority, or replacement for professional security review. Results can contain false positives and false negatives. Never submit secrets or rely on a single report for a security decision.

---

## Changelog — Major Architecture & UI Changes

### 🔄 Screenshot Engine: Playwright/Chromium → Browserless.io REST API

**What changed:**  
The original implementation launched a local Playwright-controlled Chromium binary on the server to capture screenshots and collect page signals. This was replaced with a remote [Browserless.io](https://browserless.io) headless browser service called via REST API.

**Why:**  
- **Vercel Serverless Compatibility:** Vercel does not allow bundling Chromium or persistent child processes inside serverless functions. The old Playwright approach caused deployment failures because there was no local browser binary available at runtime.
- **Full-page Screenshot Reliability:** Playwright's `full_page=True` was unreliable — it frequently captured only the visible viewport portion. The Browserless REST API (`/screenshot` endpoint) reliably returns a full-page image with a single HTTP call.
- **Reduced Cold-start Weight:** Removing Playwright and local browser binaries from the deployment keeps the serverless bundle small and fast to initialise.

**How it works now:**  
`analyzer/sandbox.py` sends a POST request to the Browserless `/screenshot` endpoint and a separate DOM evaluation call to the Browserless `/function` endpoint. The screenshot is returned as a Base64-encoded PNG data URI, which is set directly on the `<img>` element in the frontend without any intermediate file save.

**Environment variable required:**
```
BROWSERLESS_API_KEY=<your key>
```

---

### 📡 API Architecture: Async Polling → Synchronous Single Request

**What changed:**  
The original architecture split analysis into three separate routes:
- `POST /analyze/start` — start a background thread job
- `GET /analyze/status/<job_id>` — poll for live stage updates  
- `GET /screenshots/<filename>` — serve saved screenshot files

This was replaced with a single **synchronous** route: `POST /analyze`.

**Why:**  
- Vercel serverless functions cannot sustain background threads across requests. The polling architecture depended on in-process memory that doesn't survive between serverless invocations.
- The SQLite database for job persistence (`analysis_logs.db`) was also removed because serverless ephemeral filesystems don't persist writes between invocations.
- Browserless is fast enough that a single blocking request comfortably fits within Vercel's function timeout.

---

### 🎨 UI/UX Revamp: Coloured Theme → Black & White with Day/Night Toggle

**What changed:**  
The original UI used mixed greens, blues, and accent colours throughout. This was completely replaced with a strict **black-and-white** design system using CSS custom properties (`--var`).

**Why:**  
User preference. A monochrome palette looks cleaner, more professional, and is easier to extend with a theme toggle.

**Specifics:**
- **Dark mode (default):** Near-black background `#191919`, card surface `#282828`, white text.
- **Light mode:** Off-white cream background `#fcfbf8` (not harsh pure white), warm charcoal text `#2a2825`.
- All colour values live in `:root` and `[data-theme="light"]` blocks in `static/style.css`, making future updates trivial.
- Theme preference is persisted in `localStorage` under the key `bita-theme`.

---

### ☀/☾ Theme Toggle Button

**What changed:**  
Added a theme toggle button in the navbar. It shows only one icon at a time:
- **☀** when in dark mode (click to switch to light).
- **☾** when in light mode (click to switch to dark).

On hover, the icon **rotates 30 degrees** via a CSS `transform: rotate(30deg)` transition. It has no visible box, border, or background — it is a clean floating emoji.

**Why:**  
Cleaner UX. Showing both `☀ / ☾` simultaneously was ambiguous about the current state. Showing only the icon you would switch *to* makes the affordance immediately obvious.

---

### 📊 Progress Stepper (replaces old Spinner)

**What changed:**  
The old single spinner with a rotating text label was replaced with a **4-step visual progress stepper** that appears while analysis runs:

1. Connecting to isolated browser...
2. Navigating to target URL...
3. Capturing full-page screenshot...
4. Running threat analysis...

Each step transitions through three visual states:
- **Pending** — greyed out circle
- **Active** — spinning ring with bold text (the current step)
- **Done** — filled green circle with a white checkmark ✓

**How it works:**  
Since the backend returns all results in a single blocking response, the stepper is driven by a `setInterval` timer on the frontend (2.5 seconds per step). The moment the actual server response arrives, all remaining steps are instantly forced to green, a 400ms pause lets the analyst see the completed state, then the results panel fades in.

**Why not real streaming?**  
Vercel serverless functions don't support Server-Sent Events or WebSocket streaming in a way that's compatible with the current single-route design. The timed animation is the standard industry approach for this UX pattern.

---

### 🧭 Site Structure: Single Page → Multi-page with Separate Routes

**What changed:**  
Added three new pages accessible via their own Flask routes and URL paths:

| Route | Template | Purpose |
|---|---|---|
| `/faq` | `templates/faq.html` | Collapsible FAQ accordion |
| `/privacy` | `templates/privacy.html` | Privacy Policy |
| `/terms` | `templates/terms.html` | Terms of Use & Disclaimer |

**Why:**  
The disclaimer was previously embedded inline on the main analysis page. Moving legal and informational content to dedicated pages keeps the main UI focused on the core analysis workflow and makes each page independently linkable.

---

### 🗂 Navbar & Footer Layout

**What changed:**
- A fixed **navbar** was added at the top of every page containing the BITA logo (links to `/`) on the left, and FAQ link + theme toggle on the right.
- A **sticky footer** was added to every page showing: `FAQ · Privacy Policy · Terms of Use` links and the credits line.
- Both the navbar content and the main page body are constrained to `min(1000px, 92vw)` — they align on the same horizontal column so the nav never appears wider than the content.
- The layout uses a `page-wrapper` flex column with `min-height: 100vh` so the footer is always pinned to the bottom even on short pages, with no scroll overflow.

---

### 🚫 NSFW Content Blocking

**What changed:**  
Added a post-sandbox content filter in `app.py` that checks both the **final redirected URL** and the **page title** returned by the sandbox against a keyword blocklist of known adult content domains and terms.

**Why:**  
The sandbox executes and screenshots any URL submitted. Without filtering, adult content screenshots would be rendered directly in the analyst's browser. The filter intercepts the result before it is returned to the client and returns a `400` error: *"Analysis blocked: NSFW/Adult content detected."*

The check happens **after** the sandbox runs but **before** the screenshot or any result is sent to the frontend, ensuring no image ever reaches the client.

---

### 🚫 Auto-scroll Removed

**What changed:**  
When results finished loading, the original code called `resultPanel.scrollIntoView({ behavior: "smooth", block: "start" })`, which aggressively scrolled the page so the results panel hit the top of the viewport — hiding the navbar and input area.

**Why removed:**  
The results appear directly below the form in a single-screen layout. There is no need to force a scroll. Removing it keeps the analyst's view anchored where they were.

---

## Features

- Accepts a URL with or without an explicit `http://` or `https://` scheme.
- Rejects malformed URLs, unsupported schemes, oversized input, and obvious localhost targets.
- Executes the target URL in a **remote Browserless.io isolated browser** — never in the analyst's own browser.
- Captures a full-page screenshot returned as a Base64 data URI.
- Records the final URL, page title, HTTP status, redirect chain, and selected page metrics.
- Detects credential forms, auth-like forms, suspicious keywords, raw IP hosts, long URLs, external scripts, and missing HTTPS.
- Checks the final host against a configurable safe-domain Bloom filter index.
- Produces a risk score (0–100) and verdict: `Safe`, `Low to Moderate`, `Suspicious`, or `High Risk`.
- Blocks NSFW/adult content before any result reaches the client.
- Black-and-white UI with persistent day/night theme toggle.
- Analyst can copy a plain-text report or open a PDF print dialog.

---

## How It Works

```text
Analyst browser
      |
      | POST /analyze  { "url": "..." }
      v
Flask app.py
      |
      | HTTP REST call to Browserless.io /screenshot + /function
      v
Remote isolated headless Chromium (Browserless cloud)
      |
      | Base64 PNG + DOM metrics JSON
      v
NSFW filter → Behavior analysis → Risk scoring
      |
      v
Single JSON response to frontend
Frontend renders stepper → results panel
```

The analyst's browser client never receives the target page's HTML. It receives only derived metadata and a screenshot image encoded as a data URI.

---

## Requirements

- Python 3.10 or newer.
- A [Browserless.io](https://browserless.io) API key (free tier available).
- Network access from the deployment environment to Browserless's cloud endpoint.
- No local Chromium binary is needed.

Runtime Python dependencies (`requirements.txt`):

- Flask 3 or newer
- `requests` (for Browserless REST calls)

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `BROWSERLESS_API_KEY` | ✅ Yes | API key for Browserless.io |
| `SAFE_URL_SOURCE_FILE` | No | Path to safe-domain source list |
| `SAFE_URL_BLOOM_FILE` | No | Path to generated Bloom filter cache |
| `SAFE_URL_META_FILE` | No | Path to Bloom filter metadata |

---

## Installation (Local Development)

```powershell
cd C:\Users\rishi\Desktop\BITA\rbi-threat-analyzer
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Set your Browserless API key:

```powershell
$env:BROWSERLESS_API_KEY = "your_key_here"
```

Start the development server:

```powershell
python app.py
```

Open: `http://127.0.0.1:5000/`

---

## Deployment (Vercel)

BITA is designed to run as a Vercel serverless application. The `vercel.json` routes all requests to `app.py` via the Python WSGI runtime. No local browser binary is bundled — all browser execution is handled remotely by Browserless.

Set `BROWSERLESS_API_KEY` in your Vercel project's Environment Variables dashboard.

---

## HTTP API

### `GET /`
Returns the main HTML application.

### `POST /analyze`

Runs a complete synchronous analysis.

**Request:**
```json
{ "url": "https://example.com" }
```

**Successful response (abbreviated):**
```json
{
  "ok": true,
  "submitted_url": "https://example.com",
  "final_url": "https://example.com/",
  "title": "Example Domain",
  "status_code": 200,
  "screenshot_path": "data:image/png;base64,...",
  "redirect_chain": ["https://example.com/"],
  "redirect_count": 0,
  "reasons": [],
  "signals": {},
  "safe_match": { "matched": false },
  "risk_score": 2,
  "verdict": "Low to Moderate"
}
```

**Error responses:**
- `400` — invalid input, NSFW content detected, or URL blocked.
- `502` — Browserless timeout or remote browser failure.
- `500` — unexpected server error.

### `GET /faq` · `GET /privacy` · `GET /terms`
Return the respective informational HTML pages.

---

## URL Validation

`normalize_url()` applies these rules before a browser is started:

- Leading/trailing whitespace is stripped.
- Missing scheme defaults to `https://`.
- Only `http` and `https` are accepted.
- A network host is required.
- URLs longer than 2048 characters are rejected.
- `localhost`, `127.0.0.1`, `0.0.0.0`, and `::1` are rejected.

---

## Detection and Scoring

### Behavior signals (`analyzer/behavior.py`)

Reasons are flagged for:
- Two or more redirects.
- A password input detected.
- An authentication-like form (account/login/verify/password hints with email or password input).
- Suspicious keywords (`login`, `verify`, `bank`, `password`, `secure`) in title or page text.
- Twelve or more external scripts.
- Final URL host is a raw IPv4 address.
- Final URL is 140+ characters long.
- Final URL is not HTTPS.

### Score weights (`analyzer/scorer.py`)

Starts at `2`, then:

| Signal | Score change |
|---|---:|
| 2+ redirects | +12 |
| 4+ redirects | +8 additional |
| Credential form with password input | +26 |
| Auth-like form without password input | +10 |
| Any other form | +1 |
| Suspicious keywords | +3 each, capped at +12 |
| 25+ external scripts | +8 |
| 50+ external scripts | +10 additional |
| Raw IP host | +24 |
| URL length ≥ 140 chars | +10 |
| Non-HTTPS final URL | +8 |
| Safe-index match | -18 |

Verdict thresholds — 14 granular tiers across 7-point bands:

| Score | Verdict | Badge Colour |
|---|---|---|
| Safe-index match, no major flags, score < 20 | `Trusted` | 🟢 Green |
| 0 – 6 | `Clean` | 🟢 Green |
| 7 – 13 | `Very Low Risk` | 🟢 Green |
| 14 – 20 | `Low Risk` | 🟢 Green |
| 21 – 27 | `Guarded` | 🔵 Blue |
| 28 – 34 | `Moderate` | 🔵 Blue |
| 35 – 41 | `Elevated` | 🔵 Blue |
| 42 – 48 | `Suspicious` | 🟡 Yellow |
| 49 – 55 | `Concerning` | 🟡 Yellow |
| 56 – 62 | `Harmful` | 🟡 Yellow |
| 63 – 69 | `High Risk` | 🟠 Orange |
| 70 – 76 | `Very High Risk` | 🟠 Orange |
| 77 – 83 | `Dangerous` | 🟠 Orange |
| 84 – 89 | `Critical` | 🔴 Red |
| 90 – 100 | `Malicious` | 🔴 Red |

---

## Safe-Domain Intelligence

Source: `intel/safe_domains_10m.txt` — one domain or URL per line.

The application loads or builds a Bloom filter cache at startup:

- `intel/safe_domains_10m.bloom`
- `intel/safe_domains_10m.meta.json`

Bloom filters can produce false positives. A match means "possibly present in the source," not verified trustworthiness.

---

## Project Layout

```text
rbi-threat-analyzer/
├── app.py                       Flask routes, URL validation, NSFW filter
├── requirements.txt             Python dependencies
├── vercel.json                  Vercel serverless routing config
├── analyzer/
│   ├── behavior.py              Behavior signal detection
│   ├── safe_lookup.py           Bloom-filter safe-domain index
│   ├── sandbox.py               Browserless.io REST API integration
│   └── scorer.py                Risk score and verdict calculation
├── intel/
│   ├── README.md                Safe-index file format notes
│   └── safe_domains_10m.txt     Source host/domain list
├── templates/
│   ├── index.html               Main analysis interface
│   ├── faq.html                 FAQ accordion page
│   ├── privacy.html             Privacy Policy page
│   └── terms.html               Terms of Use page
└── static/
    ├── script.js                Analysis flow, stepper, theme toggle, report actions
    └── style.css                Black-and-white design system, dark/light themes
```

---

## Security and Deployment Notes

- Keep BITA behind authentication before exposing it publicly.
- The Browserless API key should be set as a secret environment variable, never committed to source control.
- NSFW filtering is keyword-based and heuristic — it is not a comprehensive content moderation system.
- `ignore_https_errors` is intentional for observation purposes but means certificate problems won't block analysis.
- The localhost blocklist only covers obvious direct targets and does not protect against DNS rebinding or redirect-based SSRF.
- Do not treat a `Safe` verdict as proof that a site is safe, uncompromised, or affiliated with a legitimate organisation.

---

## License and Ownership

No license file is currently included in the repository. The UI credits report analysis to BITA and development to Rishi Savla. Add an explicit license before distributing or accepting external contributions.

