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


class GPSReceiverHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("supported_protocols", "authenticated", "signal_strength_threshold")

    def __init__(self, authenticated=False, **kwargs):
        # TODO: add ports to abstractions?
        super().__init__(**kwargs)
        # TODO: replace when we have some way of handling state variables
        self.authenticated = authenticated

    parameter_types = {
        "signal_strength_threshold": float,
        "supported_protocols": list,  # TODO: obviously make this better
    }


class GPSReceiverAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + ("supported_protocols",)

    def __init__(self, **kwargs):
        # TODO: add ports to abstractions?
        super().__init__(**kwargs)

    def is_signal_valid(self, signal_strength):
        # Determines if the received GPS signal meets the strength threshold.
        return signal_strength >= self.parameters["signal_strength_threshold"]

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        if self.is_signal_valid(communication.signal_strength):
            if any(isinstance(communication, protocol) for protocol in self.parameters["supported_protocols"]):
                return True
        return False

    parameter_types = {
        "signal_strength_threshold": float,
        "supported_protocols": list,  # TODO: obviously make this better
    }


class GPSReceiver(CyberComponentBase):
    __slots__ = "ABSTRACTIONS"

    def __init__(self, ports: Ports | None = None, supported_protocols=None, **kwargs):
        if ports is None:
            ports = {
                "RF": Port(direction=PortDirection.IN),
                "Location": Port(direction=PortDirection.OUT),
            }
        super().__init__(ports=ports, **kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: GPSReceiverHigh(ports=ports, **kwargs),
            CyberAbstractionLevel.ALGORITHMIC: GPSReceiverAlgorithmic(ports=ports, **kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "signal_strength_threshold": float,
        "supported_protocols": list,  # TODO: obviously make this better
    }
