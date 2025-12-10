import logging

import claripy

from saci.modeling.device.component import (
    HardwareAbstractionLevel,
    HardwareCircuit,
    HardwareComponentBase,
    HardwareHigh,
    HardwarePackage,
    HardwareTechnology,
)

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================


class BatteryHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__ + (
        "charge_level",
        "voltage",
        "temperature",
        "health_status",
        "variables",
    )

    def __init__(self, charge_level=100, voltage=12.0, temperature=25.0, health_status="Good", **kwargs):
        """
        :param charge_level: Percentage of battery charge (0-100%).
        :param voltage: Nominal voltage of the battery.
        :param temperature: Operating temperature of the battery.
        :param health_status: General condition of the battery ("Good", "Warning", "Critical").
        """
        super().__init__(**kwargs)
        self.charge_level = charge_level
        self.voltage = voltage
        self.temperature = temperature
        self.health_status = health_status

        # Symbolic modeling for safety and lifetime estimation
        self.variables = {
            "battery_charge": claripy.BVS("battery_charge", 32),
            "battery_voltage": claripy.BVS("battery_voltage", 32),
            "battery_temperature": claripy.BVS("battery_temperature", 32),
            "battery_health": claripy.BVS("battery_health", 8),  # 8-bit health flag
        }


# =================== Circuit-Level Abstraction ===================


class BatteryCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__ + (
        "internal_resistance",
        "efficiency",
        "self_discharge_rate",
        "variables",
    )

    def __init__(self, internal_resistance=0.05, efficiency=95, self_discharge_rate=0.01, **kwargs):
        """
        :param internal_resistance: Internal resistance of the battery in ohms.
        :param efficiency: Efficiency percentage of the battery.
        :param self_discharge_rate: Self-discharge rate per day.
        """
        super().__init__(**kwargs)
        self.internal_resistance = internal_resistance
        self.efficiency = efficiency
        self.self_discharge_rate = self_discharge_rate

        # Symbolic modeling for failure modes and performance analysis
        self.variables = {
            "battery_resistance": claripy.BVS("battery_resistance", 32),
            "battery_efficiency": claripy.BVS("battery_efficiency", 32),
            "battery_self_discharge": claripy.BVS("battery_self_discharge", 32),
        }


# =================== Full Battery Abstraction ===================


class Battery(HardwareComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, charge_level=100, voltage=12.0, internal_resistance=0.05, efficiency=95, **kwargs):
        """
        :param charge_level: Initial battery charge percentage.
        :param voltage: Nominal voltage.
        :param internal_resistance: Internal resistance in ohms.
        :param efficiency: Efficiency percentage.
        """
        super().__init__(**kwargs)

        high_abstraction = BatteryHigh(charge_level=charge_level, voltage=voltage)
        circuit_abstraction = BatteryCircuit(internal_resistance=internal_resistance, efficiency=efficiency)

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Abstractions ===================


class BatteryHardwarePackage(HardwarePackage):
    KNOWN_BATTERY_TYPES = ["Li-ion", "LiPo", "NiMH", "Lead-Acid", "Solid-State"]

    def __init__(self, battery_type, manufacturer, **kwargs):
        """
        :param battery_type: The type of battery technology.
        :param manufacturer: The battery manufacturer.
        """
        super().__init__(chip_name=battery_type, chip_vendor=manufacturer, **kwargs)
        if battery_type not in self.KNOWN_BATTERY_TYPES:
            _l.warning(f"Unknown battery type: {battery_type}. Please add it to BatteryHardwarePackage.")


class BatteryTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["Lithium-Ion", "Lithium-Polymer", "Nickel-Metal Hydride", "Lead-Acid", "Solid-State"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of battery technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown battery technology: {technology}. Please add it to BatteryTechnology.")
