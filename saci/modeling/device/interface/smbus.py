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
from saci.modeling.communication import BaseCommunication, I2CProtocol, SMBusProtocol
import claripy
import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class SMBusHigh(CyberComponentHigh):
    __slots__ = (
        "supported_protocols",
        "communication",
        "protection",
        "bus_speed",
        "variables",
    )

    def __init__(self, supported_protocols=None, communication=None, protection=None, bus_speed=100, **kwargs):
        """
        :param supported_protocols: List of SMBus/I2C protocols supported.
        :param communication: Active communication instance.
        :param protection: Security protection (e.g., "CRC", "Address Filtering").
        :param bus_speed: Default bus speed in kHz (e.g., 100kHz for standard SMBus).
        """
        super().__init__(**kwargs)
        self.communication = communication
        self.supported_protocols = supported_protocols or [I2CProtocol, SMBusProtocol]
        self.protection = protection or "CRC"
        self.bus_speed = bus_speed

        # Symbolic variables for SMBus security and attack analysis
        self.variables = {
            "smbus_bus_speed": claripy.BVS("smbus_bus_speed", 32),
            "smbus_error_status": claripy.BVS("smbus_error_status", 8),  # Error detection flag
            "smbus_collision_detect": claripy.BVS("smbus_collision_detect", 8),  # Arbitration collision detection
        }


# =================== Algorithmic Abstraction (Cyber) ===================


class SMBusAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "supported_protocols",
        "bus_reliability",
        "variables",
    )

    def __init__(self, supported_protocols=None, bus_reliability=99.9, **kwargs):
        """
        :param supported_protocols: List of supported SMBus/I2C protocols.
        :param bus_reliability: Reliability percentage of SMBus transactions (0-100%).
        """
        super().__init__(**kwargs)
        self.supported_protocols = supported_protocols or [I2CProtocol, SMBusProtocol]
        self.bus_reliability = bus_reliability

        # Symbolic execution variables for SMBus behavior analysis
        self.variables = {
            "smbus_packet_loss": claripy.BVS("smbus_packet_loss", 32),
            "smbus_noise_level": claripy.BVS("smbus_noise_level", 8),
            "smbus_transaction_latency": claripy.BVS("smbus_transaction_latency", 32),
        }

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        """
        Determines if the communication protocol is accepted.
        """
        return any(isinstance(communication, protocol) for protocol in self.supported_protocols)


# =================== Full SMBus Abstraction (Cyber) ===================


class SMBus(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "supported_protocols")

    def __init__(self, supported_protocols=None, protection=None, bus_speed=100, **kwargs):
        super().__init__(**kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: SMBusHigh(
                supported_protocols=supported_protocols, protection=protection, bus_speed=bus_speed
            ),
            CyberAbstractionLevel.ALGORITHMIC: SMBusAlgorithmic(supported_protocols=supported_protocols),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== High-Level Abstraction (Hardware) ===================


class SMBusHardwareHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__ + ("clock_speed", "pull_up_resistors", "voltage_level")

    def __init__(self, clock_speed=100, pull_up_resistors=True, voltage_level=3.3, **kwargs):
        """
        :param clock_speed: SMBus clock speed in kHz.
        :param pull_up_resistors: Whether pull-up resistors are used for SMBus.
        :param voltage_level: Operating voltage level (e.g., 3.3V, 5V).
        """
        super().__init__(**kwargs)
        self.clock_speed = clock_speed
        self.pull_up_resistors = pull_up_resistors
        self.voltage_level = voltage_level


# =================== Circuit-Level Abstraction (Hardware) ===================


class SMBusHardwareCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__ + ("signal_impedance", "noise_filtering", "parasitic_capacitance")

    def __init__(self, signal_impedance=50, noise_filtering=True, parasitic_capacitance=5, **kwargs):
        """
        :param signal_impedance: Signal impedance in ohms.
        :param noise_filtering: Whether noise filtering is enabled.
        :param parasitic_capacitance: Estimated parasitic capacitance in pF.
        """
        super().__init__(**kwargs)
        self.signal_impedance = signal_impedance
        self.noise_filtering = noise_filtering
        self.parasitic_capacitance = parasitic_capacitance


# =================== Full SMBus Abstraction (Hardware) ===================


class SMBusHardware(HardwareComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, clock_speed=100, pull_up_resistors=True, voltage_level=3.3, **kwargs):
        super().__init__(**kwargs)

        high_abstraction = SMBusHardwareHigh(
            clock_speed=clock_speed, pull_up_resistors=pull_up_resistors, voltage_level=voltage_level
        )
        circuit_abstraction = SMBusHardwareCircuit()

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Package Abstraction ===================


class SMBusHardwarePackage(HardwarePackage):
    KNOWN_SMBUS_CHIPSETS = ["INA219", "LTC4151", "BQ76952", "ADM1066", "LM75"]

    def __init__(self, chipset_name, manufacturer, **kwargs):
        """
        :param chipset_name: The SMBus chipset name.
        :param manufacturer: The manufacturer.
        """
        super().__init__(chip_name=chipset_name, chip_vendor=manufacturer, **kwargs)
        if chipset_name not in self.KNOWN_SMBUS_CHIPSETS:
            _l.warning(f"Unknown SMBus chipset: {chipset_name}. Please add it to SMBusHardwarePackage.")


class SMBusHardwareTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["SMBus", "I2C", "PMBus"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of SMBus technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown SMBus technology: {technology}. Please add it to SMBusHardwareTechnology.")
