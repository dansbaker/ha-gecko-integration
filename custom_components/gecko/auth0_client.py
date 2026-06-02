"""Headless Auth0 PKCE flow for the Gecko mobile client.

Gecko's HA integration originally used a redirect-based OAuth2 flow against
their dedicated Auth0 client. In mid-2026 they migrated the API behind an
Auth0 Organization (`org_8ledopyspq6wArgD`) that the integration client isn't
a member of, and tokens without an ``org_id`` claim are rejected with 403.

The mobile-app Auth0 client *is* in that organization, but its only allowed
``redirect_uri`` is the iOS custom URL scheme, which HA can't host. This
client bypasses the redirect by driving Auth0's hosted login pages over plain
HTTP — the integration acts as the HTTP client, so the final
``302 Location: com.geckoportal.gecko://...?code=...`` redirect can simply be
read from the response header without ever being navigated to.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import secrets
import urllib.parse
from typing import Any

import aiohttp

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    AUTH0_CLIENT_HEADER_B64,
    AUTH0_DOMAIN,
    MOBILE_CLIENT_ID,
    MOBILE_REDIRECT_URI,
    MOBILE_USER_AGENT,
    OAUTH2_AUDIENCE,
    OAUTH2_ORGANIZATION,
)

_LOGGER = logging.getLogger(__name__)


class GeckoAuth0Error(Exception):
    """Base exception for Auth0 authentication errors."""


class GeckoAuth0InvalidCredentials(GeckoAuth0Error):
    """Invalid username/password (or expired refresh token)."""


class GeckoAuth0ConnectionError(GeckoAuth0Error):
    """Network/connection error."""


class GeckoAuth0RateLimitError(GeckoAuth0Error):
    """Auth0 rate-limit hit."""


def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class GeckoAuth0Client:
    """Drive Auth0's hosted login pages from inside HA, return tokens."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def authenticate(self, username: str, password: str) -> dict[str, Any]:
        """Run the full PKCE login flow and return the Auth0 token response."""
        code_verifier = _b64url_nopad(secrets.token_bytes(32))
        code_challenge = _b64url_nopad(hashlib.sha256(code_verifier.encode()).digest())

        try:
            state = await self._get_auth_state(code_challenge)
            auth_code = await self._submit_credentials(username, password, state)
            return await self._exchange_code_for_tokens(auth_code, code_verifier)
        except GeckoAuth0Error:
            raise
        except aiohttp.ClientError as e:
            raise GeckoAuth0ConnectionError(f"Network error: {e}") from e

    async def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        """Exchange a refresh_token for a new token bundle."""
        session = async_get_clientsession(self.hass)
        try:
            text, status = await self._post_with_retries(
                session,
                f"https://{AUTH0_DOMAIN}/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": MOBILE_CLIENT_ID,
                    "refresh_token": refresh_token,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": MOBILE_USER_AGENT,
                },
            )
        except GeckoAuth0ConnectionError:
            raise
        if status == 200:
            return json.loads(text)
        if status in (401, 403):
            raise GeckoAuth0InvalidCredentials("Refresh token rejected; user must re-auth")
        raise GeckoAuth0Error(f"Token refresh failed: HTTP {status}: {text[:200]}")

    async def _get_auth_state(self, code_challenge: str) -> str:
        session = async_get_clientsession(self.hass)
        params = {
            "client_id": MOBILE_CLIENT_ID,
            "scope": "openid profile email offline_access",
            "display": "touch",
            "audience": OAUTH2_AUDIENCE,
            "redirect_uri": MOBILE_REDIRECT_URI,
            # The organization param is the whole reason for this rewrite —
            # without it the issued JWT has no org_id claim and the API 403s.
            "organization": OAUTH2_ORGANIZATION,
            "prompt": "login",
            "response_type": "code",
            "response_mode": "query",
            "state": _b64url_nopad(secrets.token_bytes(32)),
            "nonce": _b64url_nopad(secrets.token_bytes(32)),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": AUTH0_CLIENT_HEADER_B64,
        }
        url = f"https://{AUTH0_DOMAIN}/authorize?" + urllib.parse.urlencode(params)
        headers = {
            "User-Agent": MOBILE_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
        }
        async with session.get(url, headers=headers, allow_redirects=True) as resp:
            if resp.status != 200:
                raise GeckoAuth0ConnectionError(f"Failed to get authorization page: HTTP {resp.status}")
            final_url = str(resp.url)
            m = re.search(r"state=([^&]+)", final_url)
            if not m:
                raise GeckoAuth0Error(f"No state in Auth0 login URL: {final_url[:200]}")
            return urllib.parse.unquote(m.group(1))

    async def _submit_credentials(self, username: str, password: str, state: str) -> str:
        session = async_get_clientsession(self.hass)
        base_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"https://{AUTH0_DOMAIN}",
            "User-Agent": MOBILE_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
        }

        # Step 1: submit username to identifier endpoint
        identifier_url = f"https://{AUTH0_DOMAIN}/u/login/identifier"
        text, status, _ = await self._post_with_retries(
            session,
            identifier_url,
            params={"state": state},
            data={
                "state": state,
                "username": username,
                "js-available": "true",
                "webauthn-available": "true",
                "is-brave": "false",
                "webauthn-platform-available": "false",
                "action": "default",
            },
            headers={**base_headers, "Referer": f"{identifier_url}?state={urllib.parse.quote(state)}"},
            allow_redirects=False,
            return_headers=True,
        )
        if status == 429:
            raise GeckoAuth0RateLimitError("Too many authentication attempts. Please try again later.")
        if status not in (302, 303):
            if status == 400 and text and ("invalid" in text.lower() or "wrong" in text.lower()):
                raise GeckoAuth0InvalidCredentials("Invalid username")
            raise GeckoAuth0Error(f"Identifier submission failed: HTTP {status}: {(text or '')[:200]}")

        # Step 2: submit password
        password_url = f"https://{AUTH0_DOMAIN}/u/login/password"
        text, status, headers_out = await self._post_with_retries(
            session,
            password_url,
            params={"state": state},
            data={"state": state, "username": username, "password": password, "action": "default"},
            headers={**base_headers, "Referer": f"{password_url}?state={urllib.parse.quote(state)}"},
            allow_redirects=False,
            return_headers=True,
        )
        if status == 429:
            raise GeckoAuth0RateLimitError("Too many authentication attempts. Please try again later.")
        if status == 400:
            raise GeckoAuth0InvalidCredentials("Invalid username or password")
        if status not in (302, 303):
            raise GeckoAuth0Error(f"Login failed: HTTP {status}: {(text or '')[:200]}")

        # Step 3: follow Location → /authorize/resume → final 302 with code=
        location = headers_out.get("Location", "")
        if location.startswith("/"):
            location = f"https://{AUTH0_DOMAIN}{location}"
        async with session.get(location, headers={"User-Agent": MOBILE_USER_AGENT}, allow_redirects=False) as resp:
            if resp.status not in (302, 303):
                body = await resp.text()
                raise GeckoAuth0Error(f"Authorization resume failed: HTTP {resp.status}: {body[:200]}")
            final_location = resp.headers.get("Location", "")
            if "code=" not in final_location:
                raise GeckoAuth0Error("No authorization code in callback URL")
            parsed = urllib.parse.urlparse(final_location)
            return urllib.parse.parse_qs(parsed.query)["code"][0]

    async def _exchange_code_for_tokens(self, auth_code: str, code_verifier: str) -> dict[str, Any]:
        session = async_get_clientsession(self.hass)
        text, status = await self._post_with_retries(
            session,
            f"https://{AUTH0_DOMAIN}/oauth/token",
            data={
                "client_id": MOBILE_CLIENT_ID,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": MOBILE_REDIRECT_URI,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": MOBILE_USER_AGENT,
            },
        )
        if status == 200:
            return json.loads(text)
        if status == 429:
            raise GeckoAuth0RateLimitError("Rate limited - please try again later")
        raise GeckoAuth0Error(f"Token exchange failed: HTTP {status}: {text[:200]}")

    async def _post_with_retries(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        headers: dict | None = None,
        allow_redirects: bool = True,
        return_headers: bool = False,
    ):
        """POST with bounded retries on transient network errors."""
        MAX_RETRIES = 2
        BACKOFF_BASE = 0.5
        last_exc: Exception | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                async with session.post(
                    url, params=params, data=data, headers=headers, allow_redirects=allow_redirects
                ) as resp:
                    text = await resp.text()
                    if return_headers:
                        return text, resp.status, dict(resp.headers)
                    return text, resp.status
            except aiohttp.ClientError as e:
                last_exc = e
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(BACKOFF_BASE * (2 ** attempt))
                    continue
                raise GeckoAuth0ConnectionError(f"Network error: {last_exc}") from last_exc


def decode_jwt_claims(token: str) -> dict[str, Any]:
    """Decode JWT payload without verification (we trust Auth0 over TLS)."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))
