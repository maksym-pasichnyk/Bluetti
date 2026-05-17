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
from homeassistant.const import (
    PERCENTAGE,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfFrequency,
    UnitOfPower,
)
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
        key="pack_charging_status",
        name="Pack Charging Status",
        value_fn=lambda data: data.pack_charging_status,
    ),
    BluettiSensorDescription(
        key="pack_charge_full_time",
        name="Pack Charge Full Time",
        value_fn=lambda data: data.pack_charge_full_time,
    ),
    BluettiSensorDescription(
        key="pack_discharge_empty_time",
        name="Pack Discharge Empty Time",
        value_fn=lambda data: data.pack_discharge_empty_time,
    ),
    BluettiSensorDescription(
        key="pack_aging_status",
        name="Pack Aging Status",
        value_fn=lambda data: data.pack_aging_status,
    ),
    BluettiSensorDescription(
        key="pack_aging_progress",
        name="Pack Aging Progress",
        value_fn=lambda data: data.pack_aging_progress,
    ),
    BluettiSensorDescription(
        key="pack_aging_fault",
        name="Pack Aging Fault",
        value_fn=lambda data: data.pack_aging_fault,
    ),
    BluettiSensorDescription(
        key="pack_count",
        name="Pack Count",
        value_fn=lambda data: data.pack_count,
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
    BluettiSensorDescription(
        key="total_dc_energy",
        name="Total DC Energy",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.total_dc_energy,
    ),
    BluettiSensorDescription(
        key="total_ac_energy",
        name="Total AC Energy",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.total_ac_energy,
    ),
    BluettiSensorDescription(
        key="total_pv_charging_energy",
        name="Total PV Charging Energy",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.total_pv_charging_energy,
    ),
    BluettiSensorDescription(
        key="total_grid_charging_energy",
        name="Total Grid Charging Energy",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.total_grid_charging_energy,
    ),
    BluettiSensorDescription(
        key="total_feedback_energy",
        name="Total Feedback Energy",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.total_feedback_energy,
    ),
    BluettiSensorDescription(
        key="pv_to_ac_power",
        name="PV to AC Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.pv_to_ac_power,
    ),
    BluettiSensorDescription(
        key="pv_to_ac_energy",
        name="PV to AC Energy",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.pv_to_ac_energy,
    ),
    BluettiSensorDescription(
        key="car_output_power",
        name="Car Output Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.car_output_power,
    ),
    BluettiSensorDescription(
        key="ev_output_power",
        name="EV Output Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.ev_output_power,
    ),
    BluettiSensorDescription(
        key="grid_parallel_soc",
        name="Grid Parallel SOC",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.grid_parallel_soc,
    ),
    BluettiSensorDescription(
        key="self_sufficiency_rate",
        name="Self Sufficiency Rate",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.self_sufficiency_rate,
    ),
    BluettiSensorDescription(
        key="inverter_count",
        name="Inverter Count",
        value_fn=lambda data: data.inverter_count,
    ),
    BluettiSensorDescription(
        key="inverter_power_type",
        name="Inverter Power Type",
        value_fn=lambda data: data.inverter_power_type,
    ),
    BluettiSensorDescription(
        key="charging_mode",
        name="Charging Mode",
        value_fn=lambda data: data.charging_mode,
    ),
    BluettiSensorDescription(
        key="inverter_working_status",
        name="Inverter Working Status",
        value_fn=lambda data: data.inverter_working_status,
    ),
    BluettiSensorDescription(
        key="rated_voltage",
        name="Rated Voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        value_fn=lambda data: data.rated_voltage,
    ),
    BluettiSensorDescription(
        key="rated_frequency",
        name="Rated Frequency",
        device_class=SensorDeviceClass.FREQUENCY,
        native_unit_of_measurement=UnitOfFrequency.HERTZ,
        value_fn=lambda data: data.rated_frequency,
    ),
    BluettiSensorDescription(
        key="scene_flag",
        name="Scene Flag",
        value_fn=lambda data: data.scene_flag,
    ),
    BluettiSensorDescription(
        key="sleep_standby_time",
        name="Sleep Standby Time",
        value_fn=lambda data: data.sleep_standby_time,
    ),
    BluettiSensorDescription(
        key="pack_discharge_energy_total",
        name="Pack Discharge Energy Total",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.pack_discharge_energy_total,
    ),
    BluettiSensorDescription(
        key="pack_charge_energy_total",
        name="Pack Charge Energy Total",
        value_fn=lambda data: data.pack_charge_energy_total,
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