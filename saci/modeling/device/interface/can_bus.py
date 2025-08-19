import logging
import claripy

from saci.modeling.device.component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
    HardwareComponentBase,
    HardwareAbstractionLevel,
    HardwareHigh,
    HardwareCircuit,
    HardwareTechnology,
    HardwarePackage,
)
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from saci.modeling.communication import BaseCommunication
from saci.modeling.communication.protocol import CANProtocol

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class CANBusHigh(CyberComponentHigh):
    __slots__ = (
        "communication",
        "protection",
        "bus_speed",
        "variables",
    )

    def __init__(self, communication=None, protection=None, bus_speed=500, **kwargs):
        """
        :param communication: Active communication instance.
        :param protection: Protocol protection mechanisms (e.g., CRC, ID filtering).
        :param bus_speed: CAN bus speed in kbps (e.g., 500 kbps).
        """
        super().__init__(**kwargs)
        self.communication = communication
        self.protection = protection or "CRC"
        self.bus_speed = bus_speed

        self.variables = {
            "can_bus_speed": claripy.BVS("can_bus_speed", 32),
            "can_error_frame_count": claripy.BVS("can_error_frame_count", 8),
            "can_arbitration_loss": claripy.BVS("can_arbitration_loss", 1),
        }


# =================== Algorithmic Abstraction (Cyber) ===================


class CANBusAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "bus_reliability",
        "variables",
    )

    def __init__(self, bus_reliability=99.95, **kwargs):
        """
        :param bus_reliability: Reliability percentage of CAN transactions.
        """
        super().__init__(**kwargs)
        self.bus_reliability = bus_reliability

        self.variables = {
            "can_packet_loss": claripy.BVS("can_packet_loss", 32),
            "can_noise_level": claripy.BVS("can_noise_level", 8),
            "can_latency": claripy.BVS("can_latency", 32),
        }

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        return isinstance(communication, CANProtocol)


# =================== Full CANBus Abstraction (Cyber) ===================


class CANBus(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, protection=None, bus_speed=500, **kwargs):
        super().__init__(**kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: CANBusHigh(
                protection=protection,
                bus_speed=bus_speed,
            ),
            CyberAbstractionLevel.ALGORITHMIC: CANBusAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== High-Level Abstraction (Hardware) ===================


class CANBusHardwareHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__ + ("clock_speed", "termination_resistor", "voltage_level")

    def __init__(self, clock_speed=16, termination_resistor=True, voltage_level=5.0, **kwargs):
        """
        :param clock_speed: Microcontroller clock in MHz.
        :param termination_resistor: Whether a 120-ohm termination is used.
        :param voltage_level: Operating voltage (typically 3.3V or 5V).
        """
        super().__init__(**kwargs)
        self.clock_speed = clock_speed
        self.termination_resistor = termination_resistor
        self.voltage_level = voltage_level


# =================== Circuit-Level Abstraction (Hardware) ===================


class CANBusHardwareCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__ + ("differential_signaling", "impedance", "noise_filtering")

    def __init__(self, differential_signaling=True, impedance=120, noise_filtering=True, **kwargs):
        """
        :param differential_signaling: CAN uses differential signaling (True by default).
        :param impedance: Typical characteristic impedance (Ohms).
        :param noise_filtering: Whether the circuit has filtering for EMI/noise.
        """
        super().__init__(**kwargs)
        self.differential_signaling = differential_signaling
        self.impedance = impedance
        self.noise_filtering = noise_filtering


# =================== Full CANBus Abstraction (Hardware) ===================


class CANBusHardware(HardwareComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, clock_speed=16, termination_resistor=True, voltage_level=5.0, **kwargs):
        super().__init__(**kwargs)

        high_abstraction = CANBusHardwareHigh(
            clock_speed=clock_speed,
            termination_resistor=termination_resistor,
            voltage_level=voltage_level,
        )
        circuit_abstraction = CANBusHardwareCircuit()

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Package Abstraction ===================


class CANBusHardwarePackage(HardwarePackage):
    KNOWN_CAN_CHIPSETS = ["MCP2515", "TJA1050", "SN65HVD230", "PCA82C250", "TCAN1042"]

    def __init__(self, chipset_name, manufacturer, **kwargs):
        """
        :param chipset_name: The name of the CAN transceiver or controller chip.
        :param manufacturer: Manufacturer name.
        """
        super().__init__(chip_name=chipset_name, chip_vendor=manufacturer, **kwargs)
        if chipset_name not in self.KNOWN_CAN_CHIPSETS:
            _l.warning(f"Unknown CAN chipset: {chipset_name}. Please add it to CANBusHardwarePackage.")


class CANBusHardwareTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["CAN", "CAN-FD", "ISO-TP"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: CAN technology variant.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown CAN technology: {technology}. Please add it to CANBusHardwareTechnology.")
