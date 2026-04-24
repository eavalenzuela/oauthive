"""Playwright-backed browser driver.

Optional; requires `pip install 'oauthive[browser]' && playwright install
chromium`. The importer in oauthive.browser catches ImportError and surfaces
a friendly message.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from playwright.async_api import async_playwright  # type: ignore[import-not-found]

from .base import AuthResult, BrowserDriver, BrowserError
from .manual import parse_callback


@dataclass
class PlaywrightDriver(BrowserDriver):
    username: str | None = None
    password: str | None = None
    totp_secret: str | None = None
    headless: bool = True

    async def authorize(self, url: str, *, expected_redirect_uri: str) -> AuthResult:
        prefix = urlparse(expected_redirect_uri)
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            ctx = await browser.new_context(ignore_https_errors=True)
            page = await ctx.new_page()
            try:
                await page.goto(url)
                await self._try_autofill(page)
                # Wait for navigation to the configured redirect prefix.
                await page.wait_for_url(
                    lambda u: urlparse(u).hostname == prefix.hostname
                    and urlparse(u).port == prefix.port
                    and urlparse(u).path.startswith(prefix.path or "/"),
                    timeout=60_000,
                )
                return parse_callback(page.url)
            except Exception as e:  # noqa: BLE001
                raise BrowserError(f"playwright auth failed: {e}") from e
            finally:
                await ctx.close()
                await browser.close()

    async def _try_autofill(self, page) -> None:
        """Best-effort credential fill. IdP login forms vary; operators wanting
        reliable automation should supply their own hook. We try a short list
        of common selectors for username / password / submit, then attempt a
        TOTP step when `totp_secret` is set."""
        if not self.username:
            return
        for selector in ("input[name=username]", "input[type=email]", "#username"):
            try:
                await page.fill(selector, self.username, timeout=2000)
                break
            except Exception:
                continue
        if self.password:
            for selector in ("input[name=password]", "input[type=password]", "#password"):
                try:
                    await page.fill(selector, self.password, timeout=2000)
                    break
                except Exception:
                    continue
        for selector in ("button[type=submit]", "input[type=submit]", "#submit"):
            try:
                await page.click(selector, timeout=2000)
                break
            except Exception:
                continue

        if self.totp_secret:
            # Some IdPs interstitial to a TOTP prompt. pyotp is an optional
            # dep (bundled with the [browser] extra).
            try:
                import pyotp
            except ImportError:  # pragma: no cover
                return
            code = pyotp.TOTP(self.totp_secret).now()
            filled = False
            for selector in (
                "input[name=otp]",
                "input[name=totp]",
                "input[autocomplete=one-time-code]",
                "input[type=tel][maxlength='6']",
                "#otp",
                "#totp",
            ):
                try:
                    await page.fill(selector, code, timeout=2000)
                    filled = True
                    break
                except Exception:
                    continue
            if filled:
                for selector in ("button[type=submit]", "input[type=submit]", "#submit"):
                    try:
                        await page.click(selector, timeout=2000)
                        break
                    except Exception:
                        continue
