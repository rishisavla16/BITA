const form = document.getElementById("analyzeForm");
const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const loading = document.getElementById("progressStepper"); // Used for legacy references
const progressStepper = document.getElementById("progressStepper");
const steps = [
  document.getElementById("step1"),
  document.getElementById("step2"),
  document.getElementById("step3"),
  document.getElementById("step4")
];
const livePanel = document.getElementById("livePanel");
const liveStage = document.getElementById("liveStage");
const liveShot = document.getElementById("liveShot");
const errorBox = document.getElementById("errorBox");
const resultPanel = document.getElementById("resultPanel");
const verdictBadge = document.getElementById("verdictBadge");
const finalUrl = document.getElementById("finalUrl");
const pageTitle = document.getElementById("pageTitle");
const riskScore = document.getElementById("riskScore");
const redirectCount = document.getElementById("redirectCount");
const safeMatch = document.getElementById("safeMatch");
const httpStatus = document.getElementById("httpStatus");
const riskMeterFill = document.getElementById("riskMeterFill");
const riskMeterLabel = document.getElementById("riskMeterLabel");
const signalGrid = document.getElementById("signalGrid");
const redirectChainList = document.getElementById("redirectChainList");
const analysisSummary = document.getElementById("analysisSummary");
const shot = document.getElementById("shot");
const reasonsList = document.getElementById("reasonsList");
const pasteBtn = document.getElementById("pasteBtn");
const cancelBtn = document.getElementById("cancelBtn");
const clearBtn = document.getElementById("clearBtn");
const downloadPdfBtn = document.getElementById("downloadPdfBtn");
const copyReportBtn = document.getElementById("copyReportBtn");
const screenshotPanel = document.getElementById("screenshotPanel");

const themeToggleBtn = document.getElementById("themeToggleBtn");

// ─── Theme Management ─────────────────────────────────────────────────────────
function updateThemeIcon(theme) {
  if (themeToggleBtn) {
    // If it is dark, show Sun to switch to light. If light, show Moon to switch to dark.
    themeToggleBtn.textContent = theme === "dark" ? "☀" : "☾";
  }
}

function initTheme() {
  const savedTheme = localStorage.getItem("bita-theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeIcon(savedTheme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme");
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", newTheme);
  localStorage.setItem("bita-theme", newTheme);
  updateThemeIcon(newTheme);
}

if (themeToggleBtn) {
  themeToggleBtn.addEventListener("click", toggleTheme);
}

initTheme();

// ─── FAQ Accordion ────────────────────────────────────────────────────────────
const faqQuestions = document.querySelectorAll('.faq-question');
faqQuestions.forEach(btn => {
  btn.addEventListener('click', () => {
    const faqItem = btn.parentElement;
    const answer = btn.nextElementSibling;
    
    // Toggle active state
    faqItem.classList.toggle('active');
    
    if (faqItem.classList.contains('active')) {
      answer.style.maxHeight = answer.scrollHeight + "px";
    } else {
      answer.style.maxHeight = 0;
    }
  });
});

// Tracks current report data for PDF / copy actions.
let _currentReportData = null;
// Tracks whether the user cancelled a running job.
let _cancelled = false;

// ─── Paste button ────────────────────────────────────────────────────────────
if (pasteBtn) {
  pasteBtn.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (hasElement(urlInput) && text) {
        urlInput.value = text.trim();
        urlInput.focus();
      }
    } catch {
      // Clipboard access denied — silently ignore.
    }
  });
}

// ─── Cancel button ───────────────────────────────────────────────────────────
if (cancelBtn) {
  cancelBtn.addEventListener("click", () => {
    _cancelled = true;
    showCancelledState();
  });
}

// ─── Clear button ─────────────────────────────────────────────────────────────
if (clearBtn) {
  clearBtn.addEventListener("click", () => {
    clearError();
    hideResultPanel();
    if (hasElement(urlInput)) {
      urlInput.value = "";
      urlInput.focus();
    }
    _currentReportData = null;
    showClearBtn(false);
    showCancelBtn(false);
  });
}

// ─── Download PDF button ─────────────────────────────────────────────────────
if (downloadPdfBtn) {
  downloadPdfBtn.addEventListener("click", () => {
    if (!_currentReportData) return;
    downloadReportAsPdf(_currentReportData);
  });
}

// ─── Copy report button ───────────────────────────────────────────────────────
if (copyReportBtn) {
  copyReportBtn.addEventListener("click", async () => {
    if (!_currentReportData) return;
    const text = buildReportText(_currentReportData);
    try {
      await navigator.clipboard.writeText(text);
      copyReportBtn.textContent = "✓ Copied!";
      setTimeout(() => {
        copyReportBtn.textContent = "⏎ Copy Report";
      }, 2000);
    } catch {
      copyReportBtn.textContent = "Failed";
      setTimeout(() => {
        copyReportBtn.textContent = "⏎ Copy Report";
      }, 2000);
    }
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function hasElement(node) {
  return Boolean(node);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function showCancelBtn(show) {
  if (!hasElement(cancelBtn)) return;
  cancelBtn.classList.toggle("hidden", !show);
}

function showClearBtn(show) {
  if (!hasElement(clearBtn)) return;
  clearBtn.classList.toggle("hidden", !show);
}

function setLoading(isLoading) {
  if (hasElement(progressStepper)) progressStepper.classList.toggle("hidden", !isLoading);
  if (hasElement(analyzeBtn)) analyzeBtn.disabled = isLoading;
}

function resetStepper() {
  steps.forEach(step => {
    if (step) {
      step.classList.remove("active", "done");
      step.classList.add("pending");
    }
  });
}

function updateStepper(currentIndex) {
  steps.forEach((step, index) => {
    if (!step) return;
    step.classList.remove("active", "done", "pending");
    if (index < currentIndex) {
      step.classList.add("done");
    } else if (index === currentIndex) {
      step.classList.add("active");
    } else {
      step.classList.add("pending");
    }
  });
}

function finishStepper() {
  steps.forEach(step => {
    if (step) {
      step.classList.remove("active", "pending");
      step.classList.add("done");
    }
  });
}

function clearError() {
  if (!hasElement(errorBox)) return;
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}

function showError(message) {
  if (!hasElement(errorBox)) return;
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function showCancelledState() {
  setLoading(false);
  showCancelBtn(false);
  showClearBtn(true);
  if (hasElement(livePanel)) livePanel.classList.add("hidden");
  showError("Analysis cancelled.");
}

function resetLivePanel() {
  if (hasElement(liveStage)) liveStage.textContent = "Waiting for sandbox...";
  if (hasElement(liveShot)) liveShot.removeAttribute("src");
}

// ─── Rendering ───────────────────────────────────────────────────────────────
function renderVerdict(verdict) {
  if (!hasElement(verdictBadge)) return;
  verdictBadge.textContent = verdict;
  verdictBadge.classList.remove("safe", "suspicious", "risky");
  if (verdict === "High Risk") verdictBadge.classList.add("risky");
  else if (verdict === "Suspicious") verdictBadge.classList.add("suspicious");
  else verdictBadge.classList.add("safe");
}

function renderReasons(reasons) {
  if (!hasElement(reasonsList)) return;
  reasonsList.innerHTML = "";
  if (!reasons || reasons.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No strong indicators found by current heuristics.";
    reasonsList.appendChild(li);
    return;
  }
  reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    reasonsList.appendChild(li);
  });
}

function normalizePercent(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(100, numeric));
}

function riskToneFromScore(score) {
  if (score >= 75) return "risky";
  if (score >= 45) return "suspicious";
  return "safe";
}

function renderRiskMeter(score) {
  if (!hasElement(riskMeterFill) || !hasElement(riskMeterLabel)) return;
  const normalized = normalizePercent(score);
  const tone = riskToneFromScore(normalized);
  riskMeterFill.style.width = `${normalized}%`;
  riskMeterFill.classList.remove("safe", "suspicious", "risky");
  riskMeterFill.classList.add(tone);
  riskMeterLabel.textContent = `${normalized}/100`;
}

function formatSignalValue(value) {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "None";
  if (value === null || value === undefined || value === "") return "-";
  return String(value);
}

function renderSignalBreakdown(signals = {}) {
  if (!hasElement(signalGrid)) return;
  signalGrid.innerHTML = "";
  const signalRows = [
    ["Uses HTTPS", signals.is_https],
    ["Redirect Count", signals.redirect_count],
    ["Total Forms", signals.form_count],
    ["Password Inputs", signals.password_input_count],
    ["Email Inputs", signals.email_input_count],
    ["Auth-like Forms", signals.form_auth_hint_count],
    ["Credential Form Detected", signals.has_credential_form],
    ["External Scripts", signals.external_script_count],
    ["Keyword Hits", signals.keyword_hits],
    ["IP-based URL", signals.is_ip_url],
    ["Unusually Long URL", signals.is_long_url],
    ["Safe Allowlist Hit", signals.safe_allowlist_hit],
  ];
  signalRows.forEach(([label, value]) => {
    const card = document.createElement("div");
    card.className = "signal-card";
    const labelNode = document.createElement("h4");
    labelNode.textContent = label;
    const valueNode = document.createElement("p");
    valueNode.textContent = formatSignalValue(value);
    card.appendChild(labelNode);
    card.appendChild(valueNode);
    signalGrid.appendChild(card);
  });
}

function renderRedirectChain(chain = [], finalTarget = "") {
  if (!hasElement(redirectChainList)) return;
  redirectChainList.innerHTML = "";
  const normalizedChain =
    Array.isArray(chain) && chain.length ? chain : finalTarget ? [finalTarget] : [];
  if (!normalizedChain.length) {
    const li = document.createElement("li");
    li.textContent = "No redirect data captured.";
    redirectChainList.appendChild(li);
    return;
  }
  normalizedChain.forEach((url, index) => {
    const li = document.createElement("li");
    const stepLabel = index === normalizedChain.length - 1 ? "Final" : `Hop ${index + 1}`;
    li.textContent = `${stepLabel}: ${url}`;
    redirectChainList.appendChild(li);
  });
}

function renderAnalystSummary(data) {
  if (!hasElement(analysisSummary)) return;
  const signals = data.signals || {};
  const score = normalizePercent(data.risk_score);
  const httpsText = signals.is_https ? "HTTPS enabled" : "not using HTTPS";
  const redirectText = `${signals.redirect_count ?? 0} redirect(s)`;
  const formText = signals.has_credential_form
    ? "credential form detected"
    : signals.has_auth_intent_form
    ? "authentication-like form detected"
    : "no strong auth-form cues";
  const keywordCount = Array.isArray(signals.keyword_hits) ? signals.keyword_hits.length : 0;
  const keywordsText =
    keywordCount > 0
      ? `${keywordCount} suspicious keyword hit(s)`
      : "no suspicious keyword hits";
  const safeText = signals.safe_allowlist_hit
    ? "host appears in the safe index"
    : "host not found in the safe index";

  analysisSummary.textContent =
    `Risk score is ${score}/100 (${data.verdict || "Unknown"}). ` +
    `The sandbox observed ${redirectText}, ${httpsText}, and ${formText}. ` +
    `Content analysis found ${keywordsText}; ${safeText}.`;
}

function hideResultPanel() {
  if (!hasElement(resultPanel)) return;
  resultPanel.classList.remove("visible");
  resultPanel.classList.add("hidden");
  if (hasElement(screenshotPanel)) screenshotPanel.classList.add("hidden");
}

function revealResultPanel() {
  if (!hasElement(resultPanel)) return;
  resultPanel.classList.remove("hidden");
  requestAnimationFrame(() => {
    resultPanel.classList.add("visible");
  });
  if (hasElement(screenshotPanel)) screenshotPanel.classList.remove("hidden");
}

function renderFinalResult(data) {
  _currentReportData = data;

  if (hasElement(finalUrl)) finalUrl.textContent = data.final_url || "-";
  if (hasElement(pageTitle)) pageTitle.textContent = data.title || "-";
  if (hasElement(riskScore)) riskScore.textContent = String(data.risk_score ?? "-");
  if (hasElement(redirectCount)) redirectCount.textContent = String(data.redirect_count ?? "-");
  if (hasElement(httpStatus)) httpStatus.textContent = String(data.status_code ?? "-");
  if (hasElement(safeMatch)) {
    safeMatch.textContent =
      data.safe_match && data.safe_match.matched
        ? `Yes (${data.safe_match.host}, ${data.safe_match.source})`
        : "No";
  }
  renderVerdict(data.verdict || "Unknown");
  renderReasons(data.reasons || []);
  renderRiskMeter(data.risk_score ?? 0);
  renderSignalBreakdown(data.signals || {});
  renderRedirectChain(data.redirect_chain || [], data.final_url || "");
  renderAnalystSummary(data);

  if (hasElement(livePanel)) livePanel.classList.add("hidden");

  // screenshot_path is now a Base64 data URI — set it directly.
  if (hasElement(shot) && data.screenshot_path) {
    shot.src = data.screenshot_path;
  }

  revealResultPanel();
  showCancelBtn(false);
  showClearBtn(true);
}

// ─── Report text builder (for copy / PDF) ────────────────────────────────────
function buildReportText(data) {
  const signals = data.signals || {};
  const score = normalizePercent(data.risk_score);
  const now = new Date().toLocaleString();

  const signalRows = [
    ["Uses HTTPS", signals.is_https],
    ["Redirect Count", signals.redirect_count],
    ["Total Forms", signals.form_count],
    ["Password Inputs", signals.password_input_count],
    ["Email Inputs", signals.email_input_count],
    ["Auth-like Forms", signals.form_auth_hint_count],
    ["Credential Form Detected", signals.has_credential_form],
    ["External Scripts", signals.external_script_count],
    ["Keyword Hits", signals.keyword_hits],
    ["IP-based URL", signals.is_ip_url],
    ["Unusually Long URL", signals.is_long_url],
    ["Safe Allowlist Hit", signals.safe_allowlist_hit],
  ];

  const safeText =
    data.safe_match && data.safe_match.matched
      ? `Yes (${data.safe_match.host}, ${data.safe_match.source})`
      : "No";

  const chainLines = (() => {
    const chain =
      Array.isArray(data.redirect_chain) && data.redirect_chain.length
        ? data.redirect_chain
        : data.final_url
        ? [data.final_url]
        : [];
    if (!chain.length) return "  No redirect data captured.";
    return chain
      .map((u, i) => `  ${i === chain.length - 1 ? "Final" : `Hop ${i + 1}`}: ${u}`)
      .join("\n");
  })();

  const reasons =
    !data.reasons || data.reasons.length === 0
      ? "  No strong indicators found by current heuristics."
      : data.reasons.map((r) => `  • ${r}`).join("\n");

  const summaryText = analysisSummary ? analysisSummary.textContent : "";

  return [
    `THREAT ANALYSIS REPORT`,
    `Report of: ${data.submitted_url || data.final_url || "Unknown URL"}`,
    `Generated: ${now}`,
    `${"─".repeat(60)}`,
    ``,
    `VERDICT: ${data.verdict || "Unknown"}`,
    `RISK SCORE: ${score}/100`,
    ``,
    `${"─".repeat(60)}`,
    `METADATA`,
    `${"─".repeat(60)}`,
    `Final URL:       ${data.final_url || "-"}`,
    `Page Title:      ${data.title || "-"}`,
    `HTTP Status:     ${data.status_code ?? "-"}`,
    `Redirects:       ${data.redirect_count ?? "-"}`,
    `Safe Index Hit:  ${safeText}`,
    ``,
    `${"─".repeat(60)}`,
    `REASONS`,
    `${"─".repeat(60)}`,
    reasons,
    ``,
    `${"─".repeat(60)}`,
    `SIGNAL BREAKDOWN`,
    `${"─".repeat(60)}`,
    ...signalRows.map(([label, val]) => `  ${label.padEnd(26)} ${formatSignalValue(val)}`),
    ``,
    `${"─".repeat(60)}`,
    `REDIRECT CHAIN`,
    `${"─".repeat(60)}`,
    chainLines,
    ``,
    `${"─".repeat(60)}`,
    `ANALYST SUMMARY`,
    `${"─".repeat(60)}`,
    `  ${summaryText}`,
    ``,
    `${"─".repeat(60)}`,
    `DISCLAIMER`,
    `${"─".repeat(60)}`,
    `  This report is generated by BITA (Browser Isolation & Threat Analyzer)`,
    `  and is provided for informational and educational purposes only.`,
    `  Results may contain false positives or false negatives. Do not rely`,
    `  solely on this report to make security decisions. Always conduct`,
    `  independent verification before acting on any findings.`,
    ``,
    `  Report analysis by BITA (Browser Isolation & Threat Analyzer)`,
    `  Developed by Rishi Savla`,
  ].join("\n");
}

// ─── PDF generation (no external library — uses browser print) ───────────────
function downloadReportAsPdf(data) {
  const signals = data.signals || {};
  const score = normalizePercent(data.risk_score);
  const now = new Date().toLocaleString();

  const safeText =
    data.safe_match && data.safe_match.matched
      ? `Yes (${data.safe_match.host}, ${data.safe_match.source})`
      : "No";

  const chain =
    Array.isArray(data.redirect_chain) && data.redirect_chain.length
      ? data.redirect_chain
      : data.final_url
      ? [data.final_url]
      : [];
  const chainHtml = chain.length
    ? chain.map((u, i) => `<li>${i === chain.length - 1 ? "<strong>Final</strong>" : `Hop ${i + 1}`}: ${escHtml(u)}</li>`).join("")
    : "<li>No redirect data captured.</li>";

  const reasonsHtml =
    !data.reasons || data.reasons.length === 0
      ? "<li>No strong indicators found by current heuristics.</li>"
      : data.reasons.map((r) => `<li>${escHtml(r)}</li>`).join("");

  const signalRows = [
    ["Uses HTTPS", signals.is_https],
    ["Redirect Count", signals.redirect_count],
    ["Total Forms", signals.form_count],
    ["Password Inputs", signals.password_input_count],
    ["Email Inputs", signals.email_input_count],
    ["Auth-like Forms", signals.form_auth_hint_count],
    ["Credential Form Detected", signals.has_credential_form],
    ["External Scripts", signals.external_script_count],
    ["Keyword Hits", signals.keyword_hits],
    ["IP-based URL", signals.is_ip_url],
    ["Unusually Long URL", signals.is_long_url],
    ["Safe Allowlist Hit", signals.safe_allowlist_hit],
  ];

  const signalTableRows = signalRows
    .map(([label, val]) => `<tr><td>${escHtml(label)}</td><td>${escHtml(formatSignalValue(val))}</td></tr>`)
    .join("");

  const summaryText = analysisSummary ? analysisSummary.textContent : "";

  const verdictColor =
    data.verdict === "High Risk" ? "#b91c1c" : data.verdict === "Suspicious" ? "#b45309" : "#065f46";

  const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>BITA Report — ${escHtml(data.submitted_url || data.final_url || "URL")}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: "Segoe UI", Arial, sans-serif; color: #111; background: #fff; padding: 2rem 2.5rem; font-size: 13px; line-height: 1.55; }
    h1 { font-size: 1.5rem; margin-bottom: 0.2rem; color: #111; }
    .subtitle { font-size: 0.9rem; color: #555; margin-bottom: 0.2rem; }
    .meta-line { font-size: 0.8rem; color: #888; margin-bottom: 1.5rem; }
    hr { border: none; border-top: 1.5px solid #ddd; margin: 1.2rem 0; }
    h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: 0.05em; color: #333; margin-bottom: 0.6rem; }
    .verdict-badge { display: inline-block; padding: 0.3rem 0.9rem; border-radius: 999px; font-weight: 700; color: #fff; background: ${verdictColor}; font-size: 0.9rem; margin-bottom: 1rem; }
    .score-line { font-size: 1.1rem; font-weight: 700; margin-bottom: 1.2rem; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
    td, th { text-align: left; padding: 0.4rem 0.6rem; border: 1px solid #e5e7eb; font-size: 0.84rem; }
    th { background: #f3f4f6; font-weight: 600; color: #333; }
    tr:nth-child(even) td { background: #fafafa; }
    ul, ol { padding-left: 1.4rem; margin-bottom: 0.8rem; }
    li { margin-bottom: 0.3rem; }
    p { margin-bottom: 0.6rem; }
    .summary-box { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 0.8rem 1rem; margin-bottom: 1rem; color: #333; }
    .disclaimer-box { background: #fff7ed; border: 1px solid #fed7aa; border-radius: 6px; padding: 0.8rem 1rem; margin-top: 1.5rem; font-size: 0.8rem; color: #7c2d12; }
    .footer { margin-top: 1.5rem; font-size: 0.75rem; color: #888; border-top: 1px solid #e5e7eb; padding-top: 0.8rem; }
    @media print { body { padding: 1rem; } }
  </style>
</head>
<body>
  <h1>Threat Analysis Report</h1>
  <p class="subtitle">Report of: <strong>${escHtml(data.submitted_url || data.final_url || "Unknown URL")}</strong></p>
  <p class="meta-line">Generated: ${now}</p>

  <div class="verdict-badge">${escHtml(data.verdict || "Unknown")}</div>
  <p class="score-line">Risk Score: ${score} / 100</p>

  <hr/>
  <h2>Metadata</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Final URL</td><td>${escHtml(data.final_url || "-")}</td></tr>
    <tr><td>Page Title</td><td>${escHtml(data.title || "-")}</td></tr>
    <tr><td>HTTP Status</td><td>${escHtml(String(data.status_code ?? "-"))}</td></tr>
    <tr><td>Redirects</td><td>${escHtml(String(data.redirect_count ?? "-"))}</td></tr>
    <tr><td>Safe Index Match</td><td>${escHtml(safeText)}</td></tr>
  </table>

  <hr/>
  <h2>Reasons</h2>
  <ul>${reasonsHtml}</ul>

  <hr/>
  <h2>Signal Breakdown</h2>
  <table>
    <tr><th>Signal</th><th>Value</th></tr>
    ${signalTableRows}
  </table>

  <hr/>
  <h2>Redirect Chain</h2>
  <ol>${chainHtml}</ol>

  <hr/>
  <h2>Analyst Summary</h2>
  <div class="summary-box">${escHtml(summaryText)}</div>

  <div class="disclaimer-box">
    <strong>Disclaimer:</strong> This report is generated by BITA and is provided for informational and educational
    purposes only. Results may contain false positives or false negatives. BITA does not guarantee the accuracy,
    completeness, or fitness of any analysis for a particular purpose. Do not rely solely on this report to make
    security decisions. Always conduct independent verification before acting on any findings.
  </div>

  <div class="footer">
    Report analysis by <strong>BITA</strong> (Browser Isolation &amp; Threat Analyzer) &nbsp;·&nbsp;
    Developed by <strong>Rishi Savla</strong>
  </div>
</body>
</html>`;

  const win = window.open("", "_blank");
  if (!win) {
    showError("Pop-up blocked. Please allow pop-ups and try again.");
    return;
  }
  win.document.write(htmlContent);
  win.document.close();
  win.focus();
  setTimeout(() => {
    win.print();
  }, 400);
}

function escHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── Form submit ──────────────────────────────────────────────────────────────
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();
  hideResultPanel();
  resetLivePanel();
  _cancelled = false;
  _currentReportData = null;

  const url = urlInput.value.trim();
  if (!url) {
    showError("Please provide a URL.");
    return;
  }

  setLoading(true);
  resetStepper();
  updateStepper(0);
  showCancelBtn(false);
  showClearBtn(false);

  let stageIndex = 0;
  // Progresses through steps 0, 1, 2, 3 (leaving 3 active until done)
  const stageInterval = setInterval(() => {
    if (stageIndex < steps.length - 1) {
      stageIndex++;
      updateStepper(stageIndex);
    }
  }, 2500);

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

    if (!response.ok || !data.ok) {
      throw new Error(data.error || "Analysis failed.");
    }

    finishStepper();
    // Wait briefly to show the final green tick before revealing results
    await new Promise(r => setTimeout(r, 400));
    renderFinalResult(data);
  } catch (error) {
    showError(error.message || "Unexpected error.");
    showClearBtn(true);
  } finally {
    clearInterval(stageInterval);
    setLoading(false);
    showCancelBtn(false);
  }
});
