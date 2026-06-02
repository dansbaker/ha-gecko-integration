"""Config flow for the Gecko integration.

Replaces the original OAuth2 redirect flow with a username/password form that
drives Auth0's hosted login pages directly via :class:`GeckoAuth0Client`. See
``auth0_client.py`` for the reasoning.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .api import ConfigFlowGeckoApi
from .auth0_client import (
    GeckoAuth0Client,
    GeckoAuth0ConnectionError,
    GeckoAuth0Error,
    GeckoAuth0InvalidCredentials,
    GeckoAuth0RateLimitError,
    decode_jwt_claims,
)
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

USER_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
    }
)


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Username/password config flow for Gecko."""

    VERSION = 2

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=USER_SCHEMA)

        errors: dict[str, str] = {}
        try:
            entry_data, title = await self._authenticate_and_discover(
                user_input["username"], user_input["password"]
            )
        except GeckoAuth0InvalidCredentials:
            errors["base"] = "invalid_auth"
        except GeckoAuth0RateLimitError:
            errors["base"] = "rate_limited"
        except GeckoAuth0ConnectionError:
            errors["base"] = "cannot_connect"
        except GeckoAuth0Error as err:
            _LOGGER.error("Auth0 flow failed: %s", err)
            errors["base"] = "auth0_error"
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Unexpected error during Gecko setup")
            errors["base"] = "unknown"
        else:
            await self.async_set_unique_id(entry_data["user_id"])
            self._abort_if_unique_id_configured()
            return self.async_create_entry(title=title, data=entry_data)

        return self.async_show_form(step_id="user", data_schema=USER_SCHEMA, errors=errors)

    async def _authenticate_and_discover(
        self, username: str, password: str
    ) -> tuple[dict[str, Any], str]:
        """Run Auth0 login, then discover account + vessels + spa configs."""
        auth = GeckoAuth0Client(self.hass)
        tokens = await auth.authenticate(username, password)

        access_token = tokens["access_token"]
        refresh_token = tokens.get("refresh_token")
        expires_in = float(tokens.get("expires_in", 3600))
        claims = decode_jwt_claims(access_token)
        user_id = claims["sub"]
        if "org_id" not in claims:
            # Defensive: if Gecko ever loosens the org requirement we keep working,
            # but flag it so we notice.
            _LOGGER.warning("Issued token has no org_id; API may reject calls")

        api = ConfigFlowGeckoApi(self.hass, access_token)

        # Upsert user → get accountId
        upsert = await api.async_upsert_user(user_id, email=username)
        account = upsert.get("account", {}) or {}
        account_id = account.get("accountId")
        if not account_id:
            raise GeckoAuth0Error("PUT /v2/users returned no accountId")
        account_id_str = str(account_id)

        # Vessels
        vessels = await api.async_get_vessels(account_id_str)
        vessels_with_config: list[dict[str, Any]] = []
        for vessel in vessels:
            monitor_id = vessel.get("monitorId") or vessel.get("vesselId")
            spa_config: dict[str, Any] | None = None
            if monitor_id:
                try:
                    spa_config = await api.async_get_spa_configuration(account_id_str, str(monitor_id))
                except Exception as err:  # noqa: BLE001
                    _LOGGER.warning("spa-configuration fetch failed for %s: %s", monitor_id, err)
            vessels_with_config.append({**vessel, "spa_configuration": spa_config} if spa_config else vessel)

        title = f"Gecko - {account.get('name') or username} ({len(vessels_with_config)} vessels)"
        entry_data: dict[str, Any] = {
            "tokens": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": time.time() + expires_in,
            },
            "user_id": user_id,
            "username": username,
            "account_id": account_id_str,
            "account_info": account,
            "vessels": vessels_with_config,
        }
        return entry_data, title

    async def async_step_reauth(self, _entry_data: dict[str, Any]) -> FlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if user_input is None:
            return self.async_show_form(step_id="reauth_confirm", data_schema=USER_SCHEMA)
        return await self.async_step_user(user_input)
