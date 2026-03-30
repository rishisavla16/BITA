const form = document.getElementById("analyzeForm");
const urlInput = document.getElementById("urlInput");
const loading = document.getElementById("loading");
const loadingText = document.getElementById("loadingText");
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
const shot = document.getElementById("shot");
const reasonsList = document.getElementById("reasonsList");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setLoading(isLoading) {
  loading.classList.toggle("hidden", !isLoading);
}

function clearError() {
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function resetLivePanel() {
  liveStage.textContent = "Waiting for sandbox...";
  liveShot.removeAttribute("src");
}

function renderVerdict(verdict) {
  verdictBadge.textContent = verdict;
  verdictBadge.classList.remove("safe", "suspicious", "risky");

  if (verdict === "High Risk") {
    verdictBadge.classList.add("risky");
  } else if (verdict === "Suspicious") {
    verdictBadge.classList.add("suspicious");
  } else {
    verdictBadge.classList.add("safe");
  }
}

function renderReasons(reasons) {
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

function renderFinalResult(data) {
  finalUrl.textContent = data.final_url || "-";
  pageTitle.textContent = data.title || "-";
  riskScore.textContent = String(data.risk_score ?? "-");
  redirectCount.textContent = String(data.redirect_count ?? "-");
  safeMatch.textContent = data.safe_match && data.safe_match.matched
    ? `Yes (${data.safe_match.host}, ${data.safe_match.source})`
    : "No";
  shot.src = data.screenshot_path;
  renderVerdict(data.verdict || "Unknown");
  renderReasons(data.reasons || []);
  resultPanel.classList.remove("hidden");
}

async function pollJobStatus(jobId) {
  let latestPreview = "";

  for (let i = 0; i < 60; i += 1) {
    const response = await fetch(`/analyze/status/${jobId}?t=${Date.now()}`);
    const statusData = await response.json();

    if (!response.ok || !statusData.ok) {
      throw new Error(statusData.error || "Unable to get analysis status.");
    }

    if (statusData.stage) {
      loadingText.textContent = statusData.stage;
      liveStage.textContent = statusData.stage;
    }

    if (statusData.preview_path && statusData.preview_path !== latestPreview) {
      latestPreview = statusData.preview_path;
      liveShot.src = `${latestPreview}?t=${Date.now()}`;
    }

    if (statusData.status === "completed" && statusData.result) {
      return statusData.result;
    }

    if (statusData.status === "failed") {
      throw new Error(statusData.error || "Sandbox analysis failed.");
    }

    await sleep(1200);
  }

  throw new Error("Analysis timed out while waiting for job completion.");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();
  resultPanel.classList.add("hidden");
  resetLivePanel();

  const url = urlInput.value.trim();
  if (!url) {
    showError("Please provide a URL.");
    return;
  }

  setLoading(true);
  loadingText.textContent = "Submitting analysis job";
  livePanel.classList.remove("hidden");

  try {
    const startResponse = await fetch("/analyze/start", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    });

    const startData = await startResponse.json();

    if (!startResponse.ok || !startData.ok || !startData.job_id) {
      throw new Error(startData.error || "Failed to start analysis.");
    }

    const finalResult = await pollJobStatus(startData.job_id);
    renderFinalResult(finalResult);
  } catch (error) {
    showError(error.message || "Unexpected error.");
  } finally {
    setLoading(false);
  }
});
