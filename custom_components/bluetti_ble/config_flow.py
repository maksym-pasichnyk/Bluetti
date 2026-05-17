from __future__ import annotations

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
)


class BluettiBleConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, _user_input=None):
        return self.async_abort(reason="manual_setup_not_supported")

    async def async_step_bluetooth(self, discovery_info: BluetoothServiceInfoBleak):
        address = discovery_info.address.upper()
        name = (discovery_info.name or DISCOVERY_LOCAL_NAME_PREFIX).strip() or DISCOVERY_LOCAL_NAME_PREFIX

        await self.async_set_unique_id(address)
        self._abort_if_unique_id_configured(
            updates={
                CONF_ADDRESS: address,
                CONF_DEVICE_NAME: name,
                CONF_ENCRYPTED: _is_encrypted_advertisement(discovery_info),
            }
        )

        return self.async_create_entry(
            title=name,
            data={
                CONF_ADDRESS: address,
                CONF_DEVICE_NAME: name,
                CONF_ENCRYPTED: _is_encrypted_advertisement(discovery_info),
            },
        )


def _is_encrypted_advertisement(discovery_info: BluetoothServiceInfoBleak) -> bool:
    manufacturer_data = getattr(discovery_info, "manufacturer_data", {}) or {}
    for data in manufacturer_data.values():
        payload_hex = data.hex().upper()
        if BLUETTI_MARKER_ENCRYPTED in payload_hex:
            return True
        if BLUETTI_MARKER_PLAIN in payload_hex:
            return False
    return False