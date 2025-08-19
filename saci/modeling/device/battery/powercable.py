import claripy
import logging

from saci.modeling.device.component import (
    HardwareComponentBase,
    HardwareAbstractionLevel,
    HardwareHigh,
    HardwareCircuit,
    HardwareTechnology,
    HardwarePackage,
)

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================


class PowerCableHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__ + (
        "length",
        "current_rating",
        "voltage_rating",
        "temperature",
        "condition_status",
        "variables",
    )

    def __init__(
        self, length=1.0, current_rating=10.0, voltage_rating=12.0, temperature=25.0, condition_status="Good", **kwargs
    ):
        """
        :param length: Length of the cable in meters.
        :param current_rating: Maximum current supported (Amps).
        :param voltage_rating: Maximum voltage supported (Volts).
        :param temperature: Operating temperature in Celsius.
        :param condition_status: Cable condition ("Good", "Worn", "Damaged").
        """
        super().__init__(**kwargs)
        self.length = length
        self.current_rating = current_rating
        self.voltage_rating = voltage_rating
        self.temperature = temperature
        self.condition_status = condition_status

        self.variables = {
            "cable_length": claripy.BVS("cable_length", 32),
            "cable_current_rating": claripy.BVS("cable_current_rating", 32),
            "cable_voltage_rating": claripy.BVS("cable_voltage_rating", 32),
            "cable_temperature": claripy.BVS("cable_temperature", 32),
            "cable_condition": claripy.BVS("cable_condition", 8),
        }


# =================== Circuit-Level Abstraction ===================


class PowerCableCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__ + (
        "resistance_per_meter",
        "shielding",
        "impedance",
        "variables",
    )

    def __init__(self, resistance_per_meter=0.02, shielding=True, impedance=75.0, **kwargs):
        """
        :param resistance_per_meter: Resistance of the cable per meter (Ohms).
        :param shielding: Whether the cable is shielded (True/False).
        :param impedance: Characteristic impedance in Ohms.
        """
        super().__init__(**kwargs)
        self.resistance_per_meter = resistance_per_meter
        self.shielding = shielding
        self.impedance = impedance

        self.variables = {
            "cable_resistance": claripy.BVS("cable_resistance", 32),
            "cable_impedance": claripy.BVS("cable_impedance", 32),
            "cable_shielding": claripy.BVS("cable_shielding", 1),
        }


# =================== Full PowerCable Abstraction ===================


class PowerCable(HardwareComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, length=1.0, current_rating=10.0, voltage_rating=12.0, resistance_per_meter=0.02, **kwargs):
        """
        :param length: Length of the power cable.
        :param current_rating: Max supported current.
        :param voltage_rating: Max supported voltage.
        :param resistance_per_meter: Cable resistance per meter.
        """
        super().__init__(**kwargs)

        high_abstraction = PowerCableHigh(
            length=length,
            current_rating=current_rating,
            voltage_rating=voltage_rating,
        )
        circuit_abstraction = PowerCableCircuit(
            resistance_per_meter=resistance_per_meter,
        )

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Metadata Classes ===================


class PowerCableHardwarePackage(HardwarePackage):
    KNOWN_CABLE_TYPES = ["AWG12", "AWG14", "AWG16", "AWG18", "CustomShielded"]

    def __init__(self, cable_type, manufacturer, **kwargs):
        """
        :param cable_type: Cable specification or gauge.
        :param manufacturer: Manufacturer name.
        """
        super().__init__(chip_name=cable_type, chip_vendor=manufacturer, **kwargs)
        if cable_type not in self.KNOWN_CABLE_TYPES:
            _l.warning(f"Unknown cable type: {cable_type}. Please add it to PowerCableHardwarePackage.")


class PowerCableTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["Copper", "Aluminum", "ShieldedTwistedPair", "Coaxial", "FiberOpticPower"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Physical material/technology of the cable.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown cable technology: {technology}. Please add it to PowerCableTechnology.")
