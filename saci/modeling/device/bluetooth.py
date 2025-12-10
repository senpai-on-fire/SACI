from saci.modeling.device.component.component_base import Port, PortDirection, Ports

from ..communication import BaseCommunication
from .component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class BluetoothHigh(CyberComponentHigh):
    """
    High-level properties for a Bluetooth radio/stack.
    """

    __slots__ = ("communication",)

    def __init__(self, communication=None, **kwargs):
        super().__init__(**kwargs)
        self.communication = communication

    # Example parameters you might care about at HIGH level
    parameter_types = {
        # Ex: ["BR/EDR", "BLE"]
        "supported_protocols": list,
        # Ex: ["A2DP", "HFP", "SPP", "GATT"]
        "supported_profiles": list,
        # Ex: "v5.3"
        "bt_version": str,
        # Ex: ["central", "peripheral", "audio_source", "audio_sink"]
        "roles": list,
        # Ex: "LE Secure Connections", "Just Works", "Passkey"
        "security_mode": str,
        # Ex: "AES-CCM"
        "encryption_type": str,
        # Ex: "2.4 GHz ISM"
        "frequency_band": str,
        # Ex: +8 dBm
        "tx_power_dbm": int,
    }


class BluetoothAlgorithmic(CyberComponentAlgorithmic):
    """
    Algorithmic acceptance checks: whether a given communication
    object/protocol/profile is supported by this Bluetooth component.
    """

    __slots__ = CyberComponentAlgorithmic.__slots__ + ("supported_protocols", "supported_profiles")

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        # Accept if the communication protocol or profile matches anything we support.
        # This mirrors your WiFi class pattern and keeps it flexible:
        # - protocols map to "BLE" vs "BR/EDR" stacks
        # - profiles map to A2DP/HFP/SPP/GATT, etc.
        params = self.parameters

        proto_ok = any(isinstance(communication, proto) for proto in params.get("supported_protocols", []))

        profile_ok = any(isinstance(communication, profile) for profile in params.get("supported_profiles", []))

        return proto_ok or profile_ok

    parameter_types = {
        "supported_protocols": list,
        "supported_profiles": list,
    }


class Bluetooth(CyberComponentBase):
    """
    - "RF": physical RF transceiver path
    - "Networking": logical link/data path (GATT/SPP/etc.)
    """

    def __init__(self, ports: Ports | None = None, **kwargs):
        if ports is None:
            ports = {
                "RF": Port(direction=PortDirection.INOUT),
                "Networking": Port(direction=PortDirection.INOUT),
            }
        super().__init__(ports=ports, **kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: BluetoothHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: BluetoothAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "supported_protocols": list,  # ["BR/EDR", "BLE"]
        "supported_profiles": list,  # ["A2DP", "HFP", "SPP", "GATT", ...]
        "bt_version": str,  # "v5.3"
        "roles": list,  # ["central", "peripheral", ...]
        "security_mode": str,  # "LE Secure Connections", etc.
        "encryption_type": str,  # "AES-CCM"
        "frequency_band": str,  # "2.4 GHz ISM"
        "tx_power_dbm": int,  # e.g., 8
    }
