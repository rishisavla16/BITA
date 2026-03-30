import os
import re
import uuid
from typing import Any, Callable, Dict, List, Optional

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


class SandboxAnalysisError(Exception):
    pass


def _safe_filename(prefix: str = "capture", ext: str = "png") -> str:
    token = uuid.uuid4().hex
    return f"{prefix}_{token}.{ext}"


def _collect_main_frame_redirects(url_chain: List[str], new_url: str) -> None:
    if not new_url:
        return
    if not url_chain or url_chain[-1] != new_url:
        url_chain.append(new_url)


def _write_png_bytes(file_path: str, image_bytes: bytes) -> None:
    with open(file_path, "wb") as fp:
        fp.write(image_bytes)


def _safe_emit(
    on_progress: Optional[Callable[[str, Optional[str]], None]],
    stage: str,
    preview_path: Optional[str] = None,
) -> None:
    if not on_progress:
        return
    on_progress(stage, preview_path)


def run_in_sandbox(
    target_url: str,
    screenshots_dir: str,
    timeout_ms: int = 10000,
    on_progress: Optional[Callable[[str, Optional[str]], None]] = None,
    screenshot_prefix: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Security model:
    - Treat URL as hostile input.
    - Render only in server-side headless browser context.
    - Never return raw untrusted HTML to the browser client.
    - Return only controlled artifacts (screenshot + metadata + derived metrics).
    """
    os.makedirs(screenshots_dir, exist_ok=True)
    prefix = screenshot_prefix or "capture"
    screenshot_name = _safe_filename(prefix=prefix)
    screenshot_path = os.path.join(screenshots_dir, screenshot_name)
    preview_name = _safe_filename(prefix=f"{prefix}_live")
    preview_path = os.path.join(screenshots_dir, preview_name)
    preview_web_path = f"/screenshots/{preview_name}"

    redirect_chain: List[str] = []

    try:
        _safe_emit(on_progress, "Launching isolated browser")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            # Isolated context with downloads disabled.
            context = browser.new_context(
                accept_downloads=False,
                java_script_enabled=True,
                ignore_https_errors=True,
                viewport={"width": 1440, "height": 900},
            )

            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            _safe_emit(on_progress, "Opening target URL in sandbox")

            def on_frame_navigated(frame):
                if frame == page.main_frame:
                    _collect_main_frame_redirects(redirect_chain, frame.url)

            page.on("framenavigated", on_frame_navigated)

            response = page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)

            # Live preview is a static image generated in the isolated browser.
            preview_bytes = page.screenshot(type="png", full_page=False)
            _write_png_bytes(preview_path, preview_bytes)
            _safe_emit(on_progress, "Initial page render captured", preview_web_path)

            page.wait_for_timeout(1200)

            _collect_main_frame_redirects(redirect_chain, page.url)

            title = page.title() or "(No title)"
            final_bytes = page.screenshot(type="png", full_page=True)
            _write_png_bytes(screenshot_path, final_bytes)
            _safe_emit(on_progress, "Final screenshot captured", f"/screenshots/{screenshot_name}")

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
                "screenshot_path": f"/screenshots/{screenshot_name}",
                "screenshot_disk_path": screenshot_path,
                "live_preview_path": preview_web_path,
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
        if os.path.exists(screenshot_path):
            os.remove(screenshot_path)
        if os.path.exists(preview_path):
            os.remove(preview_path)
        raise SandboxAnalysisError("Timed out while loading the URL in the isolated browser.")
    except PlaywrightError as exc:
        if os.path.exists(screenshot_path):
            os.remove(screenshot_path)
        if os.path.exists(preview_path):
            os.remove(preview_path)
        message = re.sub(r"\s+", " ", str(exc)).strip()
        raise SandboxAnalysisError(f"Playwright sandbox error: {message[:300]}")
    except Exception as exc:
        if os.path.exists(screenshot_path):
            os.remove(screenshot_path)
        if os.path.exists(preview_path):
            os.remove(preview_path)
        raise SandboxAnalysisError(f"Unexpected sandbox failure: {str(exc)[:200]}")
