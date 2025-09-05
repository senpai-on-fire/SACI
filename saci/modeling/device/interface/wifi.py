from saci.modeling.communication.protocol import WifiBProtocol, WifiGProtocol, WifiNProtocol
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
import claripy
import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class WifiHigh(CyberComponentHigh):
    __slots__ = (
        "supported_protocols",
        "protection",
        "communication",
        "encryption_type",
        "signal_strength",
        "variables",
    )

    def __init__(
        self,
        supported_protocols=None,
        communication=None,
        protection=None,
        encryption_type=None,
        signal_strength=-50,
        **kwargs,
    ):
        """
        :param supported_protocols: List of WiFi protocols supported (e.g., "802.11a/b/g/n/ac").
        :param communication: Active communication instance.
        :param protection: Security protection (e.g., "WPA2", "WPA3").
        :param encryption_type: Encryption type (e.g., "AES", "TKIP").
        :param signal_strength: Default signal strength in dBm.
        """
        super().__init__(**kwargs)
        self.communication = communication
        self.encryption_type = encryption_type
        self.supported_protocols = supported_protocols or ["802.11b", "802.11g", "802.11n"]
        self.protection = protection or "WPA2"
        self.signal_strength = signal_strength

        # Symbolic variables for WiFi attack and security testing
        self.variables = {
            "wifi_signal_strength": claripy.BVS("wifi_signal_strength", 32),
            "wifi_encryption_status": claripy.BVS("wifi_encryption_status", 8),  # 8-bit flag
            "wifi_auth_status": claripy.BVS("wifi_auth_status", 8),  # Authentication state
        }


# =================== Algorithmic Abstraction (Cyber) ===================


class WifiAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "supported_protocols",
        "interference_level",
        "variables",
    )

    def __init__(
        self, supported_protocols: list[type[BaseCommunication]] | None = None, interference_level=0, **kwargs
    ):
        """
        :param supported_protocols: List of supported WiFi protocols.
        :param interference_level: Simulated interference level (0 = no interference, 100 = max interference).
        """
        super().__init__(**kwargs)
        self.supported_protocols = supported_protocols or [WifiBProtocol, WifiGProtocol, WifiNProtocol]
        self.interference_level = interference_level

        # Symbolic execution variables for network behavior analysis
        self.variables = {
            "wifi_packet_loss": claripy.BVS("wifi_packet_loss", 32),
            "wifi_jamming_status": claripy.BVS("wifi_jamming_status", 8),
            "wifi_latency": claripy.BVS("wifi_latency", 32),
        }

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        """
        Determines if the communication protocol is accepted.
        """
        if any(isinstance(communication, protocol) for protocol in self.supported_protocols):
            return True
        return False


# =================== Full WiFi Abstraction (Cyber) ===================


class Wifi(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, supported_protocols=None, protection=None, encryption_type=None, **kwargs):
        super().__init__(**kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: WifiHigh(
                supported_protocols=supported_protocols, protection=protection, encryption_type=encryption_type
            ),
            CyberAbstractionLevel.ALGORITHMIC: WifiAlgorithmic(supported_protocols=supported_protocols),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== High-Level Abstraction (Hardware) ===================


class WifiHardwareHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__ + ("max_bandwidth", "frequency_band", "antenna_count")

    def __init__(self, max_bandwidth=100, frequency_band="2.4GHz", antenna_count=2, **kwargs):
        """
        :param max_bandwidth: Maximum WiFi bandwidth in Mbps.
        :param frequency_band: Operating frequency band (e.g., "2.4GHz", "5GHz").
        :param antenna_count: Number of antennas.
        """
        super().__init__(**kwargs)
        self.max_bandwidth = max_bandwidth
        self.frequency_band = frequency_band
        self.antenna_count = antenna_count


# =================== Circuit-Level Abstraction (Hardware) ===================


class WifiHardwareCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__ + ("rf_gain", "noise_figure", "signal_amplifier")

    def __init__(self, rf_gain=15, noise_figure=5, signal_amplifier=True, **kwargs):
        """
        :param rf_gain: Radio Frequency gain in dB.
        :param noise_figure: Noise figure in dB.
        :param signal_amplifier: Whether an amplifier is present.
        """
        super().__init__(**kwargs)
        self.rf_gain = rf_gain
        self.noise_figure = noise_figure
        self.signal_amplifier = signal_amplifier


# =================== Full WiFi Abstraction (Hardware) ===================


class WifiHardware(HardwareComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, max_bandwidth=100, frequency_band="2.4GHz", antenna_count=2, **kwargs):
        super().__init__(**kwargs)

        high_abstraction = WifiHardwareHigh(
            max_bandwidth=max_bandwidth, frequency_band=frequency_band, antenna_count=antenna_count
        )
        circuit_abstraction = WifiHardwareCircuit()

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Package Abstraction ===================


class WifiHardwarePackage(HardwarePackage):
    KNOWN_WIFI_CHIPSETS = ["ESP8266", "ESP32", "Atheros_AR9271", "Broadcom_BCM4331", "Intel_AX200"]

    def __init__(self, chipset_name, manufacturer, **kwargs):
        """
        :param chipset_name: The WiFi chipset name.
        :param manufacturer: The manufacturer.
        """
        super().__init__(chip_name=chipset_name, chip_vendor=manufacturer, **kwargs)
        if chipset_name not in self.KNOWN_WIFI_CHIPSETS:
            _l.warning(f"Unknown WiFi chipset: {chipset_name}. Please add it to WifiHardwarePackage.")


class WifiHardwareTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["802.11a", "802.11b", "802.11g", "802.11n", "802.11ac", "802.11ax"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of WiFi technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown WiFi technology: {technology}. Please add it to WifiHardwareTechnology.")
