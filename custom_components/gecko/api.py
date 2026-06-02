"""Gecko API client wrappers.

Provides ``OAuthGeckoApi`` (used by setup_entry; refreshes tokens via Auth0
when the API returns 401) and ``ConfigFlowGeckoApi`` (used during initial
auth before a ConfigEntry exists; tokens are passed in directly).

Both extend ``GeckoApiClient`` from the gecko-iot-client library, but
override:

* ``async_get_user_info`` and add ``async_upsert_user`` — the new
  ``PUT /v2/users`` endpoint, which upserts the user and returns the
  associated account in one call (replaces the retired
  ``GET /v2/user/{sub}``).
* ``async_get_monitor_livestream`` — points at ``/v2/monitors/{id}/liveStream``
  (replaces the retired ``/v1/monitors/{id}/iot/thirdPartySession``).
* ``async_get_spa_configuration`` — added; not present in the library.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from aiohttp import ClientResponseError

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from gecko_iot_client import GeckoApiClient

from .auth0_client import GeckoAuth0Client, GeckoAuth0InvalidCredentials, decode_jwt_claims
from .const import API_BASE_URL, AUTH0_DOMAIN, MOBILE_USER_AGENT

_LOGGER = logging.getLogger(__name__)

# Refresh access tokens this many seconds before their stated expiry.
_TOKEN_REFRESH_LEEWAY = 120.0


def ha_device_info() -> dict[str, Any]:
    """Body for PUT /v2/users `deviceInfo`. Gecko's schema requires
    ``platform`` to be one of a fixed set (ios/android/web etc.); they reject
    anything else, so we identify as iOS like the mobile app."""
    return {
        "deviceId": "home-assistant",
        "uuid": "home-assistant",
        "model": "Home Assistant",
        "name": "Home Assistant",
        "platform": "ios",
        "operatingSystem": "ios",
        "osVersion": "18.7",
        "manufacturer": "Home Assistant",
        "locale": "en-US",
    }


class _GeckoApiOverrides:
    """Endpoint overrides shared by config-flow and runtime clients."""

    hass: HomeAssistant

    async def async_upsert_user(
        self,
        user_id: str,
        email: str | None = None,
        first_name: str | None = None,
    ) -> dict[str, Any]:
        """PUT /v2/users — returns ``{account, user}``."""
        body: dict[str, Any] = {
            "user": {"userId": user_id},
            "deviceInfo": ha_device_info(),
        }
        if email:
            body["user"]["email"] = email
        if first_name:
            body["user"]["firstName"] = first_name
        return await self.async_request("PUT", "/v2/users", json=body)

    async def async_get_user_info(self, user_id: str) -> dict[str, Any]:  # type: ignore[override]
        """Backwards-compat alias."""
        return await self.async_upsert_user(user_id)

    async def async_get_monitor_livestream(self, monitor_id: str) -> dict[str, Any]:  # type: ignore[override]
        return await self.async_request("GET", f"/v2/monitors/{monitor_id}/liveStream")

    async def async_get_spa_configuration(self, account_id: str, monitor_id: str) -> dict[str, Any]:
        return await self.async_request(
            "GET",
            f"/accounts/{account_id}/monitors/{monitor_id}/spa-configuration",
        )


class OAuthGeckoApi(_GeckoApiOverrides, GeckoApiClient):
    """Runtime API client.

    Tokens live in ``entry.data['tokens']``. When the access token is near
    expiry (or the API returns 401), we exchange the refresh token via
    ``GeckoAuth0Client.refresh_token`` and persist the new bundle back to the
    config entry. A single lock serializes concurrent refresh attempts.
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        websession = async_get_clientsession(hass)
        super().__init__(websession, api_url=API_BASE_URL, auth0_url=f"https://{AUTH0_DOMAIN}")
        self.hass = hass
        self.entry = entry
        self._auth = GeckoAuth0Client(hass)
        self._refresh_lock = asyncio.Lock()

    # --- token management ----------------------------------------------------

    @property
    def _tokens(self) -> dict[str, Any]:
        return self.entry.data.get("tokens", {}) or {}

    def _access_token_expires_at(self) -> float:
        """Best-effort expiry epoch from the stored expires_at or JWT exp claim."""
        toks = self._tokens
        if "expires_at" in toks:
            try:
                return float(toks["expires_at"])
            except (TypeError, ValueError):
                pass
        at = toks.get("access_token", "")
        if at:
            try:
                return float(decode_jwt_claims(at).get("exp", 0))
            except Exception:
                return 0.0
        return 0.0

    async def async_get_access_token(self) -> str:
        """Return a valid access token, refreshing if it's near expiry."""
        if time.time() + _TOKEN_REFRESH_LEEWAY >= self._access_token_expires_at():
            await self._refresh_locked()
        token = self._tokens.get("access_token")
        if not token:
            raise GeckoAuth0InvalidCredentials("No access token available; user must re-auth")
        return token

    async def _refresh_locked(self) -> None:
        async with self._refresh_lock:
            # Re-check inside the lock — another coroutine may have just refreshed.
            if time.time() + _TOKEN_REFRESH_LEEWAY < self._access_token_expires_at():
                return
            refresh_token = self._tokens.get("refresh_token")
            if not refresh_token:
                raise GeckoAuth0InvalidCredentials("No refresh token stored; user must re-auth")
            _LOGGER.debug("Refreshing Gecko access token via Auth0")
            new_tokens = await self._auth.refresh_token(refresh_token)
            self._persist_tokens(new_tokens)

    def _persist_tokens(self, token_response: dict[str, Any]) -> None:
        """Merge a fresh Auth0 token bundle into the config entry."""
        existing = dict(self._tokens)
        existing.update(
            {
                "access_token": token_response["access_token"],
                "expires_at": time.time() + float(token_response.get("expires_in", 3600)),
            }
        )
        # Auth0 may or may not rotate the refresh token; only overwrite if returned.
        if "refresh_token" in token_response:
            existing["refresh_token"] = token_response["refresh_token"]
        new_data = {**self.entry.data, "tokens": existing}
        self.hass.config_entries.async_update_entry(self.entry, data=new_data)

    # --- request wrapper with 401 retry --------------------------------------

    async def async_request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        """Make an authed request; on 401, refresh once and retry."""
        try:
            return await self._do_request(method, endpoint, **kwargs)
        except ClientResponseError as e:
            if e.status != 401:
                raise
            _LOGGER.debug("Gecko API returned 401 for %s; refreshing token and retrying", endpoint)
            await self._refresh_locked()
            return await self._do_request(method, endpoint, **kwargs)

    async def _do_request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        access_token = await self.async_get_access_token()
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {access_token}"
        headers.setdefault("User-Agent", MOBILE_USER_AGENT)
        headers.setdefault("Accept", "*/*")
        url = f"{self.api_url}{endpoint}"
        async with self.websession.request(method, url, headers=headers, **kwargs) as response:
            response.raise_for_status()
            return await response.json()


class ConfigFlowGeckoApi(_GeckoApiOverrides, GeckoApiClient):
    """Used during initial setup — token passed in directly, no refresh."""

    def __init__(self, hass: HomeAssistant, access_token: str) -> None:
        websession = async_get_clientsession(hass)
        super().__init__(websession, api_url=API_BASE_URL, auth0_url=f"https://{AUTH0_DOMAIN}")
        self.hass = hass
        self._token = access_token

    async def async_get_access_token(self) -> str:
        return self._token

    async def async_request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {self._token}"
        headers.setdefault("User-Agent", MOBILE_USER_AGENT)
        headers.setdefault("Accept", "*/*")
        url = f"{self.api_url}{endpoint}"
        async with self.websession.request(method, url, headers=headers, **kwargs) as response:
            response.raise_for_status()
            return await response.json()
