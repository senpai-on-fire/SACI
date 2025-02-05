from typing import Optional, List
from claripy import BVS
import logging

from .sensor import SensorHigh, SensorAlgorithmic, Sensor
from saci.modeling.device.component import HardwarePackage, HardwareTechnology, HardwareHigh
from saci.modeling.device.component import CyberAbstractionLevel, CyberComponentSourceCode, CyberComponentBinary
from saci.modeling.communication import BaseCommunication, GPSProtocol

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================

class GPSReceiverHigh(SensorHigh):

    __slots__ = SensorHigh.__slots__ + ("supported_protocols", "authenticated", "signal_strength_threshold")

    def __init__(
        self,
        supported_protocols: Optional[List[type]] = None,
        authenticated: bool = False,
        signal_strength_threshold: int = -100,
        **kwargs
    ):
        """
        :param supported_protocols: List of protocol classes (e.g. [GPSProtocol]).
        :param authenticated: Whether the GPS receiver has authentication enabled.
        :param signal_strength_threshold: Minimum required signal strength to be considered valid.
        """
        super().__init__(**kwargs)
        self.supported_protocols = supported_protocols or []
        self.authenticated = authenticated
        self.signal_strength_threshold = signal_strength_threshold


# =================== Algorithmic Abstraction ===================

class GPSReceiverAlgorithmic(SensorAlgorithmic):

    __slots__ = SensorAlgorithmic.__slots__ + ("supported_protocols", "signal_strength_threshold")

    def __init__(
        self,
        supported_protocols: Optional[List[type]] = None,
        signal_strength_threshold: int = -100,
        **kwargs
    ):
        """
        :param supported_protocols: List of protocol classes (e.g. [GPSProtocol]).
        :param signal_strength_threshold: Minimum required signal strength to be considered valid.
        """
        super().__init__(**kwargs)
        self.supported_protocols = supported_protocols or []
        self.signal_strength_threshold = signal_strength_threshold

        # Symbolic variables for GPS receiver
        self.variables["signal_strength"] = BVS("gps_signal_strength", 32)
        self.variables["latitude"] = BVS("gps_latitude", 32)
        self.variables["longitude"] = BVS("gps_longitude", 32)
        self.variables["altitude"] = BVS("gps_altitude", 32)
        self.variables["time"] = BVS("gps_time", 64)

    def is_signal_valid(self, signal_strength):
        """
        Determines if the received GPS signal strength is valid.
        """
        return signal_strength >= self.signal_strength_threshold

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        """
        Validates if the communication is accepted based on signal strength and protocol support.
        """
        if not self.is_signal_valid(communication.signal_strength):
            return False

        return any(isinstance(communication, proto) for proto in self.supported_protocols)


# =================== Full Sensor Abstraction ===================

class GPSReceiver(Sensor):

    __slots__ = ("ABSTRACTIONS",)

    def __init__(
        self,
        supported_protocols: Optional[List[type]] = None,
        authenticated: bool = False,
        signal_strength_threshold: int = -100,
        **kwargs
    ):
        """
        :param supported_protocols: List of supported protocol classes (e.g. [GPSProtocol]).
        :param authenticated: Whether the GPS receiver has authentication enabled.
        :param signal_strength_threshold: Minimum required signal strength to be considered valid.
        """
        super().__init__(**kwargs)

        high_abstraction = GPSReceiverHigh(
            supported_protocols=supported_protocols,
            authenticated=authenticated,
            signal_strength_threshold=signal_strength_threshold
        )
        algo_abstraction = GPSReceiverAlgorithmic(
            supported_protocols=supported_protocols,
            signal_strength_threshold=signal_strength_threshold
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== Hardware Abstractions ===================

class GPSReceiverHardware(Sensor):

    __slots__ = Sensor.__slots__

    def __init__(self, uart_interface="UART1", i2c_address=None, **kwargs):
        """
        :param uart_interface: UART interface (e.g., UART1, UART2).
        :param i2c_address: I2C address if the receiver supports I2C communication.
        """
        super().__init__(**kwargs)
        self.uart_interface = uart_interface
        self.i2c_address = i2c_address
        self.variables = {}  # Initialize variables dictionary

        # Simulated hardware register values
        self.variables["hardware_status"] = BVS("gps_hw_status", 8)  # 8-bit status register
        self.variables["hardware_config"] = BVS("gps_hw_config", 16)  # 16-bit config register


class GPSReceiverHWPackage(HardwarePackage):

    KNOWN_CHIP_NAMES = [
        "Ublox_M8N", "Ublox_M9N", "Ublox_F9P", "SkyTraq_S2525F8", "Mediatek_MT3333", "Septentrio_Mosaic"
    ]

    def __init__(self, receiver_name, receiver_vendor, **kwargs):
        """
        :param receiver_name: The name of the GPS receiver chip.
        :param receiver_vendor: The manufacturer of the GPS receiver chip.
        """
        super().__init__(chip_name=receiver_name, chip_vendor=receiver_vendor, **kwargs)
        if receiver_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(f"Unknown GPS receiver chip name: {receiver_name}. Please add it to GPSReceiverHWPackage.")


class GPSReceiverHWTechnology(HardwareTechnology):

    KNOWN_TECHNOLOGIES = ["L1 Band", "L5 Band", "Dual-Band", "RTK", "PPP"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of GPS receiver technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown GPS receiver technology: {technology}. Please add it to GPSReceiverHWTechnology.")
