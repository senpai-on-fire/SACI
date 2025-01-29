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
from saci.modeling.communication import BaseCommunication, UARTProtocol, SPIProtocol, I2CProtocol
import claripy
import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================

class SerialHigh(CyberComponentHigh):

    __slots__ = ("supported_protocols", "communication", "protection", "baud_rate", "variables",)

    def __init__(self, supported_protocols=None, communication=None, protection=None, baud_rate=115200, **kwargs):
        """
        :param supported_protocols: List of serial protocols supported (e.g., UART, SPI, I2C).
        :param communication: Active communication instance.
        :param protection: Security protection (e.g., "CRC", "Parity Check").
        :param baud_rate: Default baud rate for serial communication.
        """
        super().__init__(has_external_input=True, **kwargs)
        self.communication = communication
        self.supported_protocols = supported_protocols or [UARTProtocol, SPIProtocol, I2CProtocol]
        self.protection = protection or "CRC"
        self.baud_rate = baud_rate

        # Symbolic variables for serial communication attack and security testing
        self.variables = {
            "serial_baud_rate": claripy.BVS("serial_baud_rate", 32),
            "serial_parity_status": claripy.BVS("serial_parity_status", 8),  # Parity check status
            "serial_error_flag": claripy.BVS("serial_error_flag", 8),  # Error detection flag
        }


# =================== Algorithmic Abstraction (Cyber) ===================

class SerialAlgorithmic(CyberComponentAlgorithmic):

    __slots__ = CyberComponentAlgorithmic.__slots__ + ("supported_protocols", "error_detection", "variables",)

    def __init__(self, supported_protocols=None, error_detection=True, **kwargs):
        """
        :param supported_protocols: List of supported serial protocols.
        :param error_detection: Whether error detection mechanisms (CRC, parity) are used.
        """
        super().__init__(**kwargs)
        self.supported_protocols = supported_protocols or [UARTProtocol, SPIProtocol, I2CProtocol]
        self.error_detection = error_detection

        # Symbolic execution variables for serial behavior analysis
        self.variables = {
            "serial_packet_loss": claripy.BVS("serial_packet_loss", 32),
            "serial_noise_level": claripy.BVS("serial_noise_level", 8),
            "serial_data_latency": claripy.BVS("serial_data_latency", 32),
        }

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        """
        Determines if the communication protocol is accepted.
        """
        return any(isinstance(communication, protocol) for protocol in self.supported_protocols)


# =================== Full Serial Abstraction (Cyber) ===================

class Serial(CyberComponentBase):

    __slots__ = ("ABSTRACTIONS", "has_external_input", "supported_protocols")

    def __init__(self, has_external_input=True, supported_protocols=None, protection=None, baud_rate=115200, **kwargs):
        super().__init__(**kwargs)
        
        self.has_external_input = has_external_input

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: SerialHigh(
                supported_protocols=supported_protocols, protection=protection, baud_rate=baud_rate
            ),
            CyberAbstractionLevel.ALGORITHMIC: SerialAlgorithmic(supported_protocols=supported_protocols),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== High-Level Abstraction (Hardware) ===================

class SerialHardwareHigh(HardwareHigh):

    __slots__ = HardwareHigh.__slots__ + ("voltage_level", "interface_type", "buffer_size")

    def __init__(self, voltage_level=3.3, interface_type="UART", buffer_size=64, **kwargs):
        """
        :param voltage_level: Operating voltage level (e.g., 3.3V, 5V).
        :param interface_type: Communication type (UART, SPI, I2C).
        :param buffer_size: Size of the serial buffer.
        """
        super().__init__(**kwargs)
        self.voltage_level = voltage_level
        self.interface_type = interface_type
        self.buffer_size = buffer_size


# =================== Circuit-Level Abstraction (Hardware) ===================

class SerialHardwareCircuit(HardwareCircuit):

    __slots__ = HardwareCircuit.__slots__ + ("signal_impedance", "crosstalk_level", "termination_resistor")

    def __init__(self, signal_impedance=50, crosstalk_level=5, termination_resistor=120, **kwargs):
        """
        :param signal_impedance: Signal impedance in ohms.
        :param crosstalk_level: Crosstalk level in dB.
        :param termination_resistor: Termination resistor value in ohms.
        """
        super().__init__(**kwargs)
        self.signal_impedance = signal_impedance
        self.crosstalk_level = crosstalk_level
        self.termination_resistor = termination_resistor


# =================== Full Serial Abstraction (Hardware) ===================

class SerialHardware(HardwareComponentBase):

    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, voltage_level=3.3, interface_type="UART", buffer_size=64, **kwargs):
        super().__init__(**kwargs)

        high_abstraction = SerialHardwareHigh(
            voltage_level=voltage_level, interface_type=interface_type, buffer_size=buffer_size
        )
        circuit_abstraction = SerialHardwareCircuit()

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Package Abstraction ===================

class SerialHardwarePackage(HardwarePackage):

    KNOWN_SERIAL_CHIPSETS = [
        "FT232RL", "CP2102", "MAX3232", "PL2303", "CH340G"
    ]

    def __init__(self, chipset_name, manufacturer, **kwargs):
        """
        :param chipset_name: The Serial chipset name.
        :param manufacturer: The manufacturer.
        """
        super().__init__(chip_name=chipset_name, chip_vendor=manufacturer, **kwargs)
        if chipset_name not in self.KNOWN_SERIAL_CHIPSETS:
            _l.warning(f"Unknown Serial chipset: {chipset_name}. Please add it to SerialHardwarePackage.")


class SerialHardwareTechnology(HardwareTechnology):

    KNOWN_TECHNOLOGIES = ["UART", "SPI", "I2C", "RS232", "RS485"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of Serial communication technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown Serial technology: {technology}. Please add it to SerialHardwareTechnology.")



######################################################    OLD VERSION    ########################################################################


# from saci.modeling.device.component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
# from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel
# from saci.modeling.communication import BaseCommunication, UARTProtocol


# class SerialHigh(CyberComponentHigh):
#     __slots__ = ("supported_protocols", "communication", "protection")

#     def __init__(self, supported_protocols=None, communication=None, protection=None, **kwargs):
#         super().__init__(has_external_input=True, **kwargs)
#         self.supported_protocols = supported_protocols
#         self.communication = communication
#         self.protection = protection


# class SerialAlgorithmic(CyberComponentAlgorithmic):
#     __slots__ = CyberComponentAlgorithmic.__slots__ + ("supported_protocols",)

#     def __init__(self, supported_protocols=None, **kwargs):
#         super().__init__(**kwargs)
#         self.supported_protocols = supported_protocols

#     def accepts_communication(self, communication: BaseCommunication) -> bool:
#         # TODO: depends on the protocol
#         if any(isinstance(communication, protocol) for protocol in self.supported_protocols):
#             return True
#         # TODO: depends on the protocol
#         else:
#             return False


# class Serial(CyberComponentBase):

#     __slots__ = ("ABSTRACTIONS", "has_external_input", "supported_protocols")

#     def __init__(self, has_external_input=True, supported_protocols=None, **kwargs):
#         super().__init__(**kwargs)
        
#         self.has_external_input = has_external_input

#         self.ABSTRACTIONS = {
#             CyberAbstractionLevel.HIGH: SerialHigh(supported_protocols=supported_protocols),
#             CyberAbstractionLevel.ALGORITHMIC: SerialAlgorithmic(supported_protocols=supported_protocols),
#             CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
#             CyberAbstractionLevel.BINARY: CyberComponentBinary(),
#         }
