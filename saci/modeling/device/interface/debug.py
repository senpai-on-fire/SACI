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
    HardwarePackage
)
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from saci.modeling.communication import BaseCommunication, UARTProtocol, JTAGProtocol, SWDProtocol
import claripy
import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================

class DebugHigh(CyberComponentHigh):

    __slots__ = ("supported_protocols", "communication", "protection", "access_restriction", "variables",)

    def __init__(self, supported_protocols=None, communication=None, protection=None, access_restriction="Enabled", **kwargs):
        """
        :param supported_protocols: List of debug protocols supported (e.g., UART, JTAG, SWD).
        :param communication: Active communication instance.
        :param protection: Security protection (e.g., "Debug Lock", "Access Control").
        :param access_restriction: Debug access restrictions ("Enabled", "Restricted", "Disabled").
        """
        super().__init__(**kwargs)
        self.communication = communication
        self.supported_protocols = supported_protocols or [UARTProtocol, JTAGProtocol, SWDProtocol]
        self.protection = protection or "Debug Lock"
        self.access_restriction = access_restriction

        # Symbolic variables for debug access security testing
        self.variables = {
            "debug_access_status": claripy.BVS("debug_access_status", 8),  # Debug access flag
            "debug_authentication_status": claripy.BVS("debug_authentication_status", 8),  # Authentication flag
            "debug_log_integrity": claripy.BVS("debug_log_integrity", 8),  # Log tampering detection
        }


# =================== Algorithmic Abstraction (Cyber) ===================

class DebugAlgorithmic(CyberComponentAlgorithmic):

    __slots__ = CyberComponentAlgorithmic.__slots__ + ("supported_protocols", "vulnerability_status", "variables",)

    def __init__(self, supported_protocols=None, vulnerability_status="Low", **kwargs):
        """
        :param supported_protocols: List of supported debug protocols.
        :param vulnerability_status: Debug vulnerability rating ("Low", "Medium", "High").
        """
        super().__init__(**kwargs)
        self.supported_protocols = supported_protocols or [UARTProtocol, JTAGProtocol, SWDProtocol]
        self.vulnerability_status = vulnerability_status

        # Symbolic execution variables for debug behavior analysis
        self.variables = {
            "debug_exploit_attempts": claripy.BVS("debug_exploit_attempts", 32),
            "debug_bypass_attempts": claripy.BVS("debug_bypass_attempts", 8),
            "debug_log_capture": claripy.BVS("debug_log_capture", 32),
        }

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        """
        Determines if the communication protocol is accepted.
        """
        return any(isinstance(communication, protocol) for protocol in self.supported_protocols)


# =================== Full Debug Interface Abstraction (Cyber) ===================

class Debug(CyberComponentBase):

    __slots__ = ("ABSTRACTIONS", "supported_protocols")

    def __init__(self, supported_protocols=None, protection=None, access_restriction="Enabled", **kwargs):
        super().__init__(**kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: DebugHigh(
                supported_protocols=supported_protocols, protection=protection, access_restriction=access_restriction
            ),
            CyberAbstractionLevel.ALGORITHMIC: DebugAlgorithmic(supported_protocols=supported_protocols),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== High-Level Abstraction (Hardware) ===================

class DebugHardwareHigh(HardwareHigh):

    __slots__ = HardwareHigh.__slots__ + ("interface_type", "protection_enabled", "pin_configuration")

    def __init__(self, interface_type="JTAG", protection_enabled=True, pin_configuration="Standard", **kwargs):
        """
        :param interface_type: Debugging type (JTAG, SWD, UART).
        :param protection_enabled: Whether debug protections are enabled.
        :param pin_configuration: Pin layout configuration.
        """
        super().__init__(**kwargs)
        self.interface_type = interface_type
        self.protection_enabled = protection_enabled
        self.pin_configuration = pin_configuration


# =================== Circuit-Level Abstraction (Hardware) ===================

class DebugHardwareCircuit(HardwareCircuit):

    __slots__ = HardwareCircuit.__slots__ + ("signal_impedance", "crosstalk_level", "security_fuse")

    def __init__(self, signal_impedance=50, crosstalk_level=5, security_fuse=True, **kwargs):
        """
        :param signal_impedance: Signal impedance in ohms.
        :param crosstalk_level: Crosstalk level in dB.
        :param security_fuse: Whether a security fuse is implemented to prevent access.
        """
        super().__init__(**kwargs)
        self.signal_impedance = signal_impedance
        self.crosstalk_level = crosstalk_level
        self.security_fuse = security_fuse


# =================== Full Debug Interface Abstraction (Hardware) ===================

class DebugHardware(HardwareComponentBase):

    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, interface_type="JTAG", protection_enabled=True, pin_configuration="Standard", **kwargs):
        super().__init__(**kwargs)

        high_abstraction = DebugHardwareHigh(
            interface_type=interface_type, protection_enabled=protection_enabled, pin_configuration=pin_configuration
        )
        circuit_abstraction = DebugHardwareCircuit()

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Package Abstraction ===================

class DebugHardwarePackage(HardwarePackage):

    KNOWN_DEBUG_CHIPSETS = [
        "ARM_Cortex_JTAG", "STM32_SWD", "ESP32_UART_Debug", "Atmel_ICE"
    ]

    def __init__(self, chipset_name, manufacturer, **kwargs):
        """
        :param chipset_name: The Debug chipset name.
        :param manufacturer: The manufacturer.
        """
        super().__init__(chip_name=chipset_name, chip_vendor=manufacturer, **kwargs)
        if chipset_name not in self.KNOWN_DEBUG_CHIPSETS:
            _l.warning(f"Unknown Debug chipset: {chipset_name}. Please add it to DebugHardwarePackage.")


class DebugHardwareTechnology(HardwareTechnology):

    KNOWN_TECHNOLOGIES = ["JTAG", "SWD", "UART_Debug"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of Debug technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown Debug technology: {technology}. Please add it to DebugHardwareTechnology.")
