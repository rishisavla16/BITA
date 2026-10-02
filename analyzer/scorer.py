from typing import Any, Dict


def score_risk(behavior_result: Dict[str, Any]) -> Dict[str, Any]:
    signals = behavior_result.get("signals", {})

    score = 2  # Small baseline because inputs are untrusted by default.

    if signals.get("redirect_count", 0) >= 2:
        score += 12
    if signals.get("redirect_count", 0) >= 4:
        score += 8

    if signals.get("has_credential_form"):
        score += 26
    elif signals.get("has_auth_intent_form"):
        score += 10
    elif signals.get("form_count", 0) > 0:
        score += 1

    keyword_hits = signals.get("keyword_hits", [])
    score += min(12, len(keyword_hits) * 3)

    if signals.get("external_script_count", 0) >= 25:
        score += 8
    if signals.get("external_script_count", 0) >= 50:
        score += 10

    if signals.get("is_ip_url"):
        score += 24

    if signals.get("is_long_url"):
        score += 10

    if not signals.get("is_https", True):
        score += 8

    safe_allowlist_hit = bool(signals.get("safe_allowlist_hit"))

    major_flags = (
        signals.get("is_ip_url")
        or signals.get("has_credential_form")
        or signals.get("redirect_count", 0) >= 4
        or not signals.get("is_https", True)
    )

    if safe_allowlist_hit:
        score -= 18

        # If a trusted host has no major red flags, clamp to a low score band.
        if not major_flags:
            score = min(score, 8)

    score = max(0, min(100, score))

    # 15 granular verdicts — one per 7-point band from 0 to 100
    if safe_allowlist_hit and not major_flags and score < 20:
        verdict = "Trusted"
    elif score <= 6:
        verdict = "Clean"
    elif score <= 13:
        verdict = "Very Low Risk"
    elif score <= 20:
        verdict = "Low Risk"
    elif score <= 27:
        verdict = "Guarded"
    elif score <= 34:
        verdict = "Moderate"
    elif score <= 41:
        verdict = "Elevated"
    elif score <= 48:
        verdict = "Suspicious"
    elif score <= 55:
        verdict = "Concerning"
    elif score <= 62:
        verdict = "Harmful"
    elif score <= 69:
        verdict = "High Risk"
    elif score <= 76:
        verdict = "Very High Risk"
    elif score <= 83:
        verdict = "Dangerous"
    elif score <= 89:
        verdict = "Critical"
    else:
        verdict = "Malicious"

    return {
        "risk_score": score,
        "verdict": verdict,
    }
