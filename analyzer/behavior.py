import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from analyzer.safe_lookup import SafeLookupResult


SUSPICIOUS_KEYWORDS = ["login", "verify", "bank", "password", "secure"]


def _is_ip_host(hostname: str) -> bool:
    if not hostname:
        return False
    ipv4_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    return bool(ipv4_pattern.match(hostname))


def analyze_behavior(
    submitted_url: str,
    sandbox_result: Dict[str, Any],
    safe_match: SafeLookupResult | None = None,
) -> Dict[str, Any]:
    reasons: List[str] = []

    final_url = sandbox_result.get("final_url", submitted_url) or submitted_url
    title = (sandbox_result.get("title") or "").lower()
    text_excerpt = (sandbox_result.get("text_excerpt") or "").lower()

    redirect_count = int(sandbox_result.get("redirect_count", 0))
    form_count = int(sandbox_result.get("form_count", 0))
    password_input_count = int(sandbox_result.get("password_input_count", 0))
    email_input_count = int(sandbox_result.get("email_input_count", 0))
    form_auth_hint_count = int(sandbox_result.get("form_auth_hint_count", 0))
    external_script_count = int(sandbox_result.get("external_script_count", 0))

    parsed = urlparse(final_url)
    hostname = parsed.hostname or ""

    if redirect_count >= 2:
        reasons.append(f"Multiple redirects detected ({redirect_count}).")

    has_credential_form = password_input_count > 0
    has_auth_intent_form = form_auth_hint_count > 0 and (email_input_count > 0 or password_input_count > 0)

    if has_credential_form:
        reasons.append(
            "Credential-style form detected (password input present), which may indicate phishing intent."
        )
    elif has_auth_intent_form:
        reasons.append(
            "Authentication-like form detected with email/account cues."
        )

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in title or kw in text_excerpt]
    if keyword_hits:
        reasons.append("Suspicious keywords present: " + ", ".join(keyword_hits) + ".")

    if external_script_count >= 12:
        reasons.append(f"High number of external scripts ({external_script_count}).")

    if _is_ip_host(hostname):
        reasons.append("Final URL uses a raw IP address instead of a domain.")

    if len(final_url) >= 140:
        reasons.append("Final URL is unusually long.")

    if parsed.scheme != "https":
        reasons.append("Page is not using HTTPS.")

    safe_hit = bool(safe_match and safe_match.matched)

    signals = {
        "redirect_count": redirect_count,
        "form_count": form_count,
        "password_input_count": password_input_count,
        "email_input_count": email_input_count,
        "form_auth_hint_count": form_auth_hint_count,
        "has_credential_form": has_credential_form,
        "has_auth_intent_form": has_auth_intent_form,
        "external_script_count": external_script_count,
        "keyword_hits": keyword_hits,
        "is_ip_url": _is_ip_host(hostname),
        "is_long_url": len(final_url) >= 140,
        "is_https": parsed.scheme == "https",
        "safe_allowlist_hit": safe_hit,
    }

    return {
        "reasons": reasons,
        "signals": signals,
        "safe_match": {
            "matched": safe_hit,
            "source": safe_match.source if safe_match else "none",
            "host": safe_match.host if safe_match else hostname,
        },
    }
