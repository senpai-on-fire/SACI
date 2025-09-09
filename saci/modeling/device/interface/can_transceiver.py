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


class CANTransceiverHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__ + (
        "transceiver_model",
        "voltage_range",
        "data_rate",
        "mode",
        "variables",
    )

    def __init__(
        self,
        transceiver_model="MCP2551",
        voltage_range=(4.5, 5.5),
        data_rate=1_000,  # kbps
        mode="Normal",
        **kwargs,
    ):
        """
        :param transceiver_model: Identifier for the CAN transceiver chip.
        :param voltage_range: Operating voltage range (min, max) in volts.
        :param data_rate: Supported CAN data rate in kbps.
        :param mode: Operating mode (e.g., "Normal", "Standby", "Silent").
        """
        super().__init__(**kwargs)
        self.transceiver_model = transceiver_model
        self.voltage_range = voltage_range
        self.data_rate = data_rate
        self.mode = mode

        self.variables = {
            "can_transceiver_model": claripy.BVS("can_transceiver_model", 32),
            "can_data_rate": claripy.BVS("can_data_rate", 32),
            "can_operating_mode": claripy.BVS("can_operating_mode", 8),
            "can_voltage_low": claripy.BVS("can_voltage_low", 32),
            "can_voltage_high": claripy.BVS("can_voltage_high", 32),
        }


# =================== Circuit-Level Abstraction ===================


class CANTransceiverCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__ + (
        "tx_rx_delay",
        "bus_driver_strength",
        "short_circuit_protection",
        "variables",
    )

    def __init__(
        self,
        tx_rx_delay=200,  # ns
        bus_driver_strength=40,  # mA
        short_circuit_protection=True,
        **kwargs,
    ):
        """
        :param tx_rx_delay: Transmission to reception propagation delay (ns).
        :param bus_driver_strength: Max current drive strength in mA.
        :param short_circuit_protection: Whether short-circuit protection is supported.
        """
        super().__init__(**kwargs)
        self.tx_rx_delay = tx_rx_delay
        self.bus_driver_strength = bus_driver_strength
        self.short_circuit_protection = short_circuit_protection

        self.variables = {
            "can_tx_rx_delay": claripy.BVS("can_tx_rx_delay", 32),
            "can_driver_strength": claripy.BVS("can_driver_strength", 32),
            "can_short_circuit_flag": claripy.BVS("can_short_circuit_flag", 1),
        }


# =================== Full Transceiver Abstraction ===================


class CANTransceiver(HardwareComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(
        self,
        transceiver_model="MCP2551",
        voltage_range=(4.5, 5.5),
        data_rate=1_000,
        **kwargs,
    ):
        super().__init__(**kwargs)

        high_abstraction = CANTransceiverHigh(
            transceiver_model=transceiver_model,
            voltage_range=voltage_range,
            data_rate=data_rate,
        )
        circuit_abstraction = CANTransceiverCircuit()

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Metadata ===================


class CANTransceiverPackage(HardwarePackage):
    KNOWN_TRANSCEIVERS = [
        "MCP2551",
        "TJA1050",
        "SN65HVD230",
        "MAX3051",
        "TCAN1042",
    ]

    def __init__(self, transceiver_model, manufacturer, **kwargs):
        """
        :param transceiver_model: CAN transceiver chip name.
        :param manufacturer: Chip vendor.
        """
        super().__init__(chip_name=transceiver_model, chip_vendor=manufacturer, **kwargs)
        if transceiver_model not in self.KNOWN_TRANSCEIVERS:
            _l.warning(
                f"Unknown CAN transceiver model: {transceiver_model}. "
                "Please add it to CANTransceiverPackage.KNOWN_TRANSCEIVERS.",
            )


class CANTransceiverTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = [
        "High-Speed CAN",
        "Low-Speed Fault-Tolerant CAN",
        "CAN-FD",
        "Isolated CAN",
    ]

    def __init__(self, technology, **kwargs):
        """
        :param technology: CAN transceiver implementation category.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(
                f"Unknown CAN transceiver technology: {technology}. "
                "Please add it to CANTransceiverTechnology.KNOWN_TECHNOLOGIES.",
            )
