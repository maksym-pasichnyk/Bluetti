from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfElectricCurrent, UnitOfElectricPotential, UnitOfPower
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .client import BluettiHomeData
from .const import CONF_ADDRESS, CONF_DEVICE_NAME, DOMAIN


@dataclass(frozen=True, kw_only=True)
class BluettiSensorDescription(SensorEntityDescription):
    value_fn: Callable[[BluettiHomeData], int | float | str | None]


SENSORS: tuple[BluettiSensorDescription, ...] = (
    BluettiSensorDescription(
        key="battery_soc",
        name="Battery SOC",
        device_class=SensorDeviceClass.BATTERY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.battery_soc,
    ),
    BluettiSensorDescription(
        key="battery_voltage",
        name="Battery Voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.battery_voltage,
    ),
    BluettiSensorDescription(
        key="battery_current",
        name="Battery Current",
        device_class=SensorDeviceClass.CURRENT,
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.battery_current,
    ),
    BluettiSensorDescription(
        key="ac_output_power",
        name="AC Output Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.ac_output_power,
    ),
    BluettiSensorDescription(
        key="dc_output_power",
        name="DC Output Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.dc_output_power,
    ),
    BluettiSensorDescription(
        key="pv_input_power",
        name="PV Input Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.pv_input_power,
    ),
    BluettiSensorDescription(
        key="grid_power",
        name="Grid Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.grid_power,
    ),
    BluettiSensorDescription(
        key="inverter_power",
        name="Inverter Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.inverter_power,
    ),
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(BluettiBleSensor(coordinator, entry, description) for description in SENSORS)


class BluettiBleSensor(CoordinatorEntity, SensorEntity):
    entity_description: BluettiSensorDescription
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry: ConfigEntry, description: BluettiSensorDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        address = entry.data[CONF_ADDRESS]
        self._attr_unique_id = f"{address}-{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, address)},
            name=entry.data[CONF_DEVICE_NAME],
            manufacturer="Bluetti",
            model="AC200L",
        )

    @property
    def native_value(self):
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)