from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import ConfigFlow

from .const import (
    BLUETTI_MARKER_ENCRYPTED,
    BLUETTI_MARKER_PLAIN,
    CONF_ADDRESS,
    CONF_DEVICE_NAME,
    CONF_ENCRYPTED,
    DISCOVERY_LOCAL_NAME_PREFIX,
    DOMAIN,
    SERVICE_UUID,
)


class BluettiBleConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._discovered_devices: dict[str, BluetoothServiceInfoBleak] = {}
        self._bluetooth_discovery: BluetoothServiceInfoBleak | None = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        self._discovered_devices = self._async_get_discovered_devices()

        if user_input is not None:
            discovery_info = self._discovered_devices.get(user_input[CONF_ADDRESS])
            if discovery_info is not None:
                return await self._async_create_entry_from_discovery(
                    discovery_info,
                    raise_on_progress=False,
                )

        if not self._discovered_devices:
            return self.async_abort(reason="no_devices_found")

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ADDRESS): vol.In(
                        {
                            address: _discovery_label(discovery_info)
                            for address, discovery_info in sorted(
                                self._discovered_devices.items(),
                                key=lambda item: _discovery_label(item[1]).lower(),
                            )
                        }
                    )
                }
            ),
        )

    async def async_step_bluetooth(self, discovery_info: BluetoothServiceInfoBleak):
        self._bluetooth_discovery = discovery_info

        entry_data = _entry_data_from_discovery(discovery_info)
        await self.async_set_unique_id(entry_data[CONF_ADDRESS])
        self._abort_if_unique_id_configured(updates=entry_data)

        self.context["title_placeholders"] = {"name": entry_data[CONF_DEVICE_NAME]}
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(self, user_input: dict[str, Any] | None = None):
        if self._bluetooth_discovery is None:
            return self.async_abort(reason="no_devices_found")

        if user_input is not None:
            entry_data = _entry_data_from_discovery(self._bluetooth_discovery)
            self._abort_if_unique_id_configured(updates=entry_data)
            return self.async_create_entry(
                title=entry_data[CONF_DEVICE_NAME],
                data=entry_data,
            )

        entry_data = _entry_data_from_discovery(self._bluetooth_discovery)
        return self.async_show_form(
            step_id="bluetooth_confirm",
            data_schema=vol.Schema({}),
            description_placeholders={
                "name": entry_data[CONF_DEVICE_NAME],
                "address": entry_data[CONF_ADDRESS],
            },
        )

    async def _async_create_entry_from_discovery(
        self,
        discovery_info: BluetoothServiceInfoBleak,
        *,
        raise_on_progress: bool = True,
    ):
        entry_data = _entry_data_from_discovery(discovery_info)

        await self.async_set_unique_id(entry_data[CONF_ADDRESS], raise_on_progress=raise_on_progress)
        self._abort_if_unique_id_configured(
            updates=entry_data
        )

        return self.async_create_entry(
            title=entry_data[CONF_DEVICE_NAME],
            data=entry_data,
        )

    def _async_get_discovered_devices(self) -> dict[str, BluetoothServiceInfoBleak]:
        configured_addresses = {
            entry.unique_id
            for entry in self._async_current_entries(include_ignore=False)
            if entry.unique_id
        }

        discovered_devices: dict[str, BluetoothServiceInfoBleak] = {}
        for discovery_info in bluetooth.async_discovered_service_info(self.hass, connectable=True):
            if not _is_supported_discovery(discovery_info):
                continue

            address = discovery_info.address.upper()
            if address in configured_addresses:
                continue

            discovered_devices[address] = discovery_info

        return discovered_devices


def _is_encrypted_advertisement(discovery_info: BluetoothServiceInfoBleak) -> bool:
    manufacturer_data = getattr(discovery_info, "manufacturer_data", {}) or {}
    for data in manufacturer_data.values():
        payload_hex = data.hex().upper()
        if BLUETTI_MARKER_ENCRYPTED in payload_hex:
            return True
        if BLUETTI_MARKER_PLAIN in payload_hex:
            return False
    return False


def _is_supported_discovery(discovery_info: BluetoothServiceInfoBleak) -> bool:
    name = (discovery_info.name or "").strip()
    if not name.startswith(DISCOVERY_LOCAL_NAME_PREFIX):
        return False

    service_uuids = {
        service_uuid.lower()
        for service_uuid in (getattr(discovery_info, "service_uuids", None) or [])
    }
    return SERVICE_UUID.lower() in service_uuids


def _discovery_label(discovery_info: BluetoothServiceInfoBleak) -> str:
    name = (discovery_info.name or DISCOVERY_LOCAL_NAME_PREFIX).strip() or DISCOVERY_LOCAL_NAME_PREFIX
    return f"{name} ({discovery_info.address.upper()})"


def _entry_data_from_discovery(discovery_info: BluetoothServiceInfoBleak) -> dict[str, str | bool]:
    name = (discovery_info.name or DISCOVERY_LOCAL_NAME_PREFIX).strip() or DISCOVERY_LOCAL_NAME_PREFIX
    return {
        CONF_ADDRESS: discovery_info.address.upper(),
        CONF_DEVICE_NAME: name,
        CONF_ENCRYPTED: _is_encrypted_advertisement(discovery_info),
    }