import os
import re
import base64
from typing import Any, Callable, Dict, List, Optional

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


class SandboxAnalysisError(Exception):
    pass


def _collect_main_frame_redirects(url_chain: List[str], new_url: str) -> None:
    if not new_url:
        return
    if not url_chain or url_chain[-1] != new_url:
        url_chain.append(new_url)


def run_in_sandbox(
    target_url: str,
    timeout_ms: int = 30000,
) -> Dict[str, Any]:
    """
    Security model:
    - Treat URL as hostile input.
    - Render only in server-side headless browser context via Browserless.io
    - Return only controlled artifacts (Base64 screenshot + metadata + derived metrics).
    """
    redirect_chain: List[str] = []

    try:
        with sync_playwright() as p:
            # connect_over_cdp uses the base Browserless CDP endpoint (no /playwright path)
            browserless_token = os.environ.get("BROWSERLESS_TOKEN", "2VMYsMrwkslXaUT5e2a1daa283e833939394b0060811d02e0")
            browser = p.chromium.connect_over_cdp(f"wss://production-sfo.browserless.io?token={browserless_token}")
            
            context = browser.new_context(
                accept_downloads=False,
                java_script_enabled=True,
                ignore_https_errors=True,
                viewport={"width": 1440, "height": 900},
            )

            page = context.new_page()
            page.set_default_timeout(timeout_ms)

            def on_frame_navigated(frame):
                if frame == page.main_frame:
                    _collect_main_frame_redirects(redirect_chain, frame.url)

            page.on("framenavigated", on_frame_navigated)

            response = page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)

            page.wait_for_timeout(1200)

            _collect_main_frame_redirects(redirect_chain, page.url)

            title = page.title() or "(No title)"
            
            # Capture screenshot as raw bytes and convert to Base64 data URI
            final_bytes = page.screenshot(type="png", full_page=True)
            screenshot_b64 = "data:image/png;base64," + base64.b64encode(final_bytes).decode("utf-8")

            page_metrics = page.evaluate(
                """
                () => {
                    const forms = Array.from(document.querySelectorAll('form'));
                    const scripts = Array.from(document.querySelectorAll('script[src]'));
                    const externalScripts = scripts.filter((s) => {
                        const src = s.getAttribute('src') || '';
                        return src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//');
                    }).length;
                    const passwordInputs = document.querySelectorAll('input[type="password"]').length;
                    const emailInputs = document.querySelectorAll('input[type="email"]').length;
                    const authHints = forms.filter((form) => {
                        const blob = `${form.getAttribute('id') || ''} ${form.getAttribute('name') || ''} ${form.getAttribute('action') || ''} ${form.innerText || ''}`.toLowerCase();
                        return /login|log in|signin|sign in|verify|account|password/.test(blob);
                    }).length;
                    const text = (document.body?.innerText || '').slice(0, 50000);
                    return {
                        form_count: forms.length,
                        password_input_count: passwordInputs,
                        email_input_count: emailInputs,
                        form_auth_hint_count: authHints,
                        external_script_count: externalScripts,
                        text_excerpt: text,
                    };
                }
                """
            )

            status_code = response.status if response else None
            final_url = page.url

            context.close()
            browser.close()

            return {
                "final_url": final_url,
                "title": title,
                "status_code": status_code,
                "screenshot_path": screenshot_b64, # Base64 injected directly into img src
                "redirect_chain": redirect_chain,
                "redirect_count": max(0, len(redirect_chain) - 1),
                "form_count": int(page_metrics.get("form_count", 0)),
                "password_input_count": int(page_metrics.get("password_input_count", 0)),
                "email_input_count": int(page_metrics.get("email_input_count", 0)),
                "form_auth_hint_count": int(page_metrics.get("form_auth_hint_count", 0)),
                "external_script_count": int(page_metrics.get("external_script_count", 0)),
                "text_excerpt": str(page_metrics.get("text_excerpt", "")),
            }

    except PlaywrightTimeoutError:
        raise SandboxAnalysisError("Timed out while loading the URL in the isolated browser.")
    except PlaywrightError as exc:
        message = re.sub(r"\s+", " ", str(exc)).strip()
        raise SandboxAnalysisError(f"Playwright sandbox error: {message[:300]}")
    except Exception as exc:
        raise SandboxAnalysisError(f"Unexpected sandbox failure: {str(exc)[:200]}")
