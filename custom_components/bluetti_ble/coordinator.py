from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import BluettiBleClient, BluettiBleError, BluettiHomeData
from .const import CONF_ADDRESS, CONF_ENCRYPTED, DOMAIN, UPDATE_INTERVAL

_LOGGER = logging.getLogger(__name__)


class BluettiBleCoordinator(DataUpdateCoordinator[BluettiHomeData]):
    def __init__(self, hass, entry: ConfigEntry) -> None:
        self.client = BluettiBleClient(
            hass,
            entry.data[CONF_ADDRESS],
            entry.data[CONF_ENCRYPTED],
        )
        super().__init__(
            hass,
            logger=_LOGGER,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
        )

    async def _async_update_data(self) -> BluettiHomeData:
        try:
            return await self.client.async_read_home_data()
        except BluettiBleError as err:
            raise UpdateFailed(str(err)) from err

    async def async_shutdown(self) -> None:
        await self.client.async_disconnect()