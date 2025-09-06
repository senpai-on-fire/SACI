import logging

import claripy

from saci.modeling.device.component import (
    CyberAbstractionLevel,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
    HardwareAbstractionLevel,
    HardwareCircuit,
    HardwareComponentBase,
    HardwareHigh,
    HardwarePackage,
    HardwareTechnology,
)

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class BMSHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + (
        "charging_mode",
        "safety_status",
        "variables",
    )

    def __init__(self, charging_mode="Idle", safety_status="Normal", **kwargs):
        """
        :param charging_mode: Operating mode of the BMS ("Idle", "Charging", "Discharging", "Balancing").
        :param safety_status: General condition of the battery system ("Normal", "Warning", "Critical").
        """
        super().__init__(**kwargs)
        self.charging_mode = charging_mode
        self.safety_status = safety_status

        # Symbolic variables for safety state
        self.variables = {
            "bms_mode": claripy.BVS("bms_mode", 8),  # Charging state
            "bms_safety": claripy.BVS("bms_safety", 8),  # 8-bit safety status
            "bms_temperature": claripy.BVS("bms_temperature", 32),
        }


# =================== Algorithmic Abstraction (Cyber) ===================


class BMSAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "voltage_balance",
        "current_regulation",
        "temperature_control",
        "variables",
    )

    def __init__(self, voltage_balance=True, current_regulation=True, temperature_control=True, **kwargs):
        """
        :param voltage_balance: Whether the BMS balances the voltage across cells.
        :param current_regulation: Whether the BMS manages charge/discharge current.
        :param temperature_control: Whether the BMS controls temperature.
        """
        super().__init__(**kwargs)

        self.voltage_balance = voltage_balance
        self.current_regulation = current_regulation
        self.temperature_control = temperature_control

        # Symbolic variables for real-time control
        self.variables = {
            "bms_voltage_balance": claripy.BVS("bms_voltage_balance", 8),  # 8-bit control flag
            "bms_current": claripy.BVS("bms_current", 32),  # Current regulation
            "bms_cell_voltage": claripy.BVS("bms_cell_voltage", 32 * 6),  # 6-cell system example
            "bms_discharge_rate": claripy.BVS("bms_discharge_rate", 32),
            "bms_overtemp_flag": claripy.BVS("bms_overtemp_flag", 8),
        }


# =================== Full Cyber BMS Abstraction ===================


class BMS(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, charging_mode="Idle", safety_status="Normal", **kwargs):
        """
        :param charging_mode: Initial charging state.
        :param safety_status: Initial safety state.
        """
        super().__init__(**kwargs)

        high_abstraction = BMSHigh(charging_mode=charging_mode, safety_status=safety_status)
        algo_abstraction = BMSAlgorithmic()

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== High-Level Abstraction (Hardware) ===================


class BMSHardwareHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__ + ("battery_type", "max_cells", "communication_interface")

    def __init__(self, battery_type="Li-ion", max_cells=6, communication_interface="I2C", **kwargs):
        """
        :param battery_type: Type of battery the BMS manages.
        :param max_cells: Number of battery cells in the system.
        :param communication_interface: Interface used (I2C, SPI, CAN).
        """
        super().__init__(**kwargs)
        self.battery_type = battery_type
        self.max_cells = max_cells
        self.communication_interface = communication_interface


# =================== Circuit-Level Abstraction (Hardware) ===================


class BMSHardwareCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__ + ("balancing_enabled", "overvoltage_protection", "short_circuit_protection")

    def __init__(self, balancing_enabled=True, overvoltage_protection=True, short_circuit_protection=True, **kwargs):
        """
        :param balancing_enabled: Whether the BMS balances the battery cells.
        :param overvoltage_protection: Protection against overvoltage.
        :param short_circuit_protection: Protection against short circuits.
        """
        super().__init__(**kwargs)

        self.balancing_enabled = balancing_enabled
        self.overvoltage_protection = overvoltage_protection
        self.short_circuit_protection = short_circuit_protection


# =================== Full Hardware BMS Abstraction ===================


class BMSHardware(HardwareComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, battery_type="Li-ion", max_cells=6, communication_interface="I2C", **kwargs):
        """
        :param battery_type: Type of battery the BMS manages.
        :param max_cells: Number of battery cells in the system.
        :param communication_interface: Interface used (I2C, SPI, CAN).
        """
        super().__init__(**kwargs)

        high_abstraction = BMSHardwareHigh(
            battery_type=battery_type, max_cells=max_cells, communication_interface=communication_interface
        )
        circuit_abstraction = BMSHardwareCircuit()

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Package Abstraction ===================


class BMSHardwarePackage(HardwarePackage):
    KNOWN_BMS_TYPES = ["Smart BMS", "Passive BMS", "Active BMS"]

    def __init__(self, bms_type, manufacturer, **kwargs):
        """
        :param bms_type: The type of BMS technology.
        :param manufacturer: The BMS manufacturer.
        """
        super().__init__(chip_name=bms_type, chip_vendor=manufacturer, **kwargs)
        if bms_type not in self.KNOWN_BMS_TYPES:
            _l.warning(f"Unknown BMS type: {bms_type}. Please add it to BMSHardwarePackage.")


class BMSHardwareTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["Passive Balancing", "Active Balancing", "Integrated BMS", "External BMS"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of BMS technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown BMS technology: {technology}. Please add it to BMSHardwareTechnology.")
