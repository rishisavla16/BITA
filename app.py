import os
from flask import Flask, jsonify, render_template, request
from urllib.parse import urlparse

from analyzer.behavior import analyze_behavior
from analyzer.safe_lookup import SafeLookupResult, build_default_safe_index
from analyzer.scorer import score_risk
from analyzer.sandbox import SandboxAnalysisError, run_in_sandbox

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAFE_URL_INDEX = build_default_safe_index(BASE_DIR)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # Prevent oversized request bodies.


def normalize_url(raw_url: str) -> str:
    candidate = (raw_url or "").strip()
    if not candidate:
        raise ValueError("URL is required.")

    if len(candidate) > 2048:
        raise ValueError("URL is too long.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are allowed.")

    if not parsed.netloc:
        raise ValueError("Invalid URL format.")

    # Reject obvious local/unsafe host targets.
    lowered_host = parsed.hostname.lower() if parsed.hostname else ""
    blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if lowered_host in blocked_hosts:
        raise ValueError("Localhost targets are not allowed.")

    return parsed.geturl()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_url():
    payload = request.get_json(silent=True) or {}
    submitted_url = (payload.get("url") or "").strip()

    try:
        normalized_url = normalize_url(submitted_url)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    try:
        # Run synchronously. Browserless is very fast, so this should finish within Vercel's timeout.
        sandbox_result = run_in_sandbox(normalized_url, timeout_ms=30000)

        safe_match = SAFE_URL_INDEX.might_be_safe(sandbox_result.get("final_url", normalized_url))
        behavior = analyze_behavior(normalized_url, sandbox_result, safe_match)
        scoring = score_risk(behavior)

        response = {
            "ok": True,
            "submitted_url": submitted_url,
            "normalized_url": normalized_url,
            "final_url": sandbox_result.get("final_url", normalized_url),
            "title": sandbox_result.get("title", ""),
            "status_code": sandbox_result.get("status_code"),
            "screenshot_path": sandbox_result.get("screenshot_path", ""),  # This is now a Base64 data URI
            "redirect_chain": sandbox_result.get("redirect_chain", []),
            "redirect_count": sandbox_result.get("redirect_count", 0),
            "reasons": behavior.get("reasons", []),
            "signals": behavior.get("signals", {}),
            "safe_match": behavior.get("safe_match", {}),
            "risk_score": scoring["risk_score"],
            "verdict": scoring["verdict"],
        }
        return jsonify(response)

    except SandboxAnalysisError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    except Exception as e:
        return jsonify({"ok": False, "error": "Analysis failed safely. Try another URL."}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
