import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request, send_from_directory

from analyzer.behavior import analyze_behavior
from analyzer.safe_lookup import SafeLookupResult, build_default_safe_index
from analyzer.scorer import score_risk
from analyzer.sandbox import SandboxAnalysisError, run_in_sandbox


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "screenshots")
DB_PATH = os.path.join(BASE_DIR, "analysis_logs.db")

os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
SAFE_URL_INDEX = build_default_safe_index(BASE_DIR)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # Prevent oversized request bodies.

ANALYSIS_JOBS: Dict[str, Dict[str, Any]] = {}
ANALYSIS_LOCK = threading.Lock()
JOB_RETENTION_SECONDS = 1800


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submitted_url TEXT NOT NULL,
                normalized_url TEXT NOT NULL,
                final_url TEXT,
                page_title TEXT,
                risk_score INTEGER,
                verdict TEXT,
                reasons TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


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


def persist_log(submitted_url: str, normalized_url: str, result: dict) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO analysis_logs (
                submitted_url,
                normalized_url,
                final_url,
                page_title,
                risk_score,
                verdict,
                reasons,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                submitted_url,
                normalized_url,
                result.get("final_url", ""),
                result.get("title", ""),
                result.get("risk_score", 0),
                result.get("verdict", "Unknown"),
                " | ".join(result.get("reasons", [])),
                datetime.utcnow().isoformat() + "Z",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _prune_old_jobs() -> None:
    cutoff = time.time() - JOB_RETENTION_SECONDS
    with ANALYSIS_LOCK:
        stale_ids = [
            job_id
            for job_id, job in ANALYSIS_JOBS.items()
            if job.get("completed_at") and job.get("completed_at", 0) < cutoff
        ]
        for job_id in stale_ids:
            ANALYSIS_JOBS.pop(job_id, None)


def _create_job(submitted_url: str, normalized_url: str) -> str:
    job_id = uuid.uuid4().hex
    now = time.time()
    with ANALYSIS_LOCK:
        ANALYSIS_JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "stage": "Queued",
            "submitted_url": submitted_url,
            "normalized_url": normalized_url,
            "preview_path": "",
            "result": None,
            "error": "",
            "created_at": now,
            "updated_at": now,
            "completed_at": None,
        }
    return job_id


def _update_job(job_id: str, **fields: Any) -> None:
    with ANALYSIS_LOCK:
        job = ANALYSIS_JOBS.get(job_id)
        if not job:
            return
        job.update(fields)
        job["updated_at"] = time.time()


def _get_job(job_id: str) -> Dict[str, Any] | None:
    with ANALYSIS_LOCK:
        job = ANALYSIS_JOBS.get(job_id)
        if not job:
            return None
        return dict(job)


def _build_analysis_response(submitted_url: str, normalized_url: str) -> Dict[str, Any]:
    sandbox_result = run_in_sandbox(normalized_url, SCREENSHOTS_DIR, timeout_ms=10000)
    safe_match = SAFE_URL_INDEX.might_be_safe(sandbox_result.get("final_url", normalized_url))
    behavior = analyze_behavior(normalized_url, sandbox_result, safe_match)
    scoring = score_risk(behavior)

    return {
        "ok": True,
        "submitted_url": submitted_url,
        "normalized_url": normalized_url,
        "final_url": sandbox_result.get("final_url", normalized_url),
        "title": sandbox_result.get("title", ""),
        "screenshot_path": sandbox_result.get("screenshot_path", ""),
        "redirect_chain": sandbox_result.get("redirect_chain", []),
        "redirect_count": sandbox_result.get("redirect_count", 0),
        "reasons": behavior.get("reasons", []),
        "signals": behavior.get("signals", {}),
        "safe_match": behavior.get("safe_match", {}),
        "risk_score": scoring["risk_score"],
        "verdict": scoring["verdict"],
    }


def _run_async_analysis_job(job_id: str) -> None:
    job = _get_job(job_id)
    if not job:
        return

    submitted_url = str(job.get("submitted_url", ""))
    normalized_url = str(job.get("normalized_url", ""))

    _update_job(job_id, status="running", stage="Initializing isolated browser")

    def on_progress(stage: str, preview_path: str | None = None) -> None:
        payload: Dict[str, Any] = {"stage": stage}
        if preview_path:
            payload["preview_path"] = preview_path
        _update_job(job_id, **payload)

    try:
        sandbox_result = run_in_sandbox(
            normalized_url,
            SCREENSHOTS_DIR,
            timeout_ms=10000,
            on_progress=on_progress,
            screenshot_prefix=f"job_{job_id[:10]}",
        )
        safe_match = SAFE_URL_INDEX.might_be_safe(sandbox_result.get("final_url", normalized_url))
        behavior = analyze_behavior(normalized_url, sandbox_result, safe_match)
        scoring = score_risk(behavior)

        response = {
            "ok": True,
            "submitted_url": submitted_url,
            "normalized_url": normalized_url,
            "final_url": sandbox_result.get("final_url", normalized_url),
            "title": sandbox_result.get("title", ""),
            "screenshot_path": sandbox_result.get("screenshot_path", ""),
            "redirect_chain": sandbox_result.get("redirect_chain", []),
            "redirect_count": sandbox_result.get("redirect_count", 0),
            "reasons": behavior.get("reasons", []),
            "signals": behavior.get("signals", {}),
            "safe_match": behavior.get("safe_match", {}),
            "risk_score": scoring["risk_score"],
            "verdict": scoring["verdict"],
        }

        persist_log(submitted_url, normalized_url, response)
        _update_job(
            job_id,
            status="completed",
            stage="Analysis complete",
            result=response,
            completed_at=time.time(),
        )
    except SandboxAnalysisError as exc:
        _update_job(
            job_id,
            status="failed",
            stage="Sandbox failed",
            error=str(exc),
            completed_at=time.time(),
        )
    except Exception:
        _update_job(
            job_id,
            status="failed",
            stage="Analysis failed safely",
            error="Analysis failed safely. Try another URL.",
            completed_at=time.time(),
        )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/screenshots/<path:filename>")
def screenshots(filename: str):
    # Serve only files from our controlled screenshots directory.
    return send_from_directory(SCREENSHOTS_DIR, filename)


@app.route("/analyze", methods=["POST"])
def analyze_url():
    payload = request.get_json(silent=True) or {}
    submitted_url = (payload.get("url") or "").strip()

    try:
        normalized_url = normalize_url(submitted_url)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    try:
        response = _build_analysis_response(submitted_url, normalized_url)

        persist_log(submitted_url, normalized_url, response)
        return jsonify(response)

    except SandboxAnalysisError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    except Exception:
        # Avoid leaking internals to the client.
        return jsonify({"ok": False, "error": "Analysis failed safely. Try another URL."}), 500


@app.route("/analyze/start", methods=["POST"])
def analyze_start():
    _prune_old_jobs()
    payload = request.get_json(silent=True) or {}
    submitted_url = (payload.get("url") or "").strip()

    try:
        normalized_url = normalize_url(submitted_url)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    job_id = _create_job(submitted_url, normalized_url)
    worker = threading.Thread(target=_run_async_analysis_job, args=(job_id,), daemon=True)
    worker.start()

    return jsonify({"ok": True, "job_id": job_id})


@app.route("/analyze/status/<job_id>", methods=["GET"])
def analyze_status(job_id: str):
    _prune_old_jobs()
    job = _get_job(job_id)
    if not job:
        return jsonify({"ok": False, "error": "Job not found or expired."}), 404

    payload = {
        "ok": True,
        "job_id": job_id,
        "status": job.get("status", "unknown"),
        "stage": job.get("stage", ""),
        "preview_path": job.get("preview_path", ""),
        "error": job.get("error", ""),
    }

    if job.get("status") == "completed" and job.get("result"):
        payload["result"] = job.get("result")

    return jsonify(payload)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
