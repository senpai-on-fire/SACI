from typing import Optional

from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports
from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication, GPSProtocol

class GPSReceiverHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("supported_protocols", "authenticated", "signal_strength_threshold")

    def __init__(self, authenticated=False, **kwargs):
        # TODO: add ports to abstractions?
        super().__init__(**kwargs)
        # TODO: replace when we have some way of handling state variables
        self.authenticated = authenticated

    @property
    def parameter_types(self):
        return {
            "signal_strength_threshold": float,
            "supported_protocols": list, # TODO: obviously make this better
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

    @property
    def parameter_types(self):
        return {
            "signal_strength_threshold": float,
            "supported_protocols": list, # TODO: obviously make this better
        }

class GPSReceiver(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS")

    def __init__(self, ports: Optional[Ports]=None, supported_protocols=None, **kwargs):
        super().__init__(
            ports=union_ports({
                "RF": Port(direction=PortDirection.IN),
                "Location": Port(direction=PortDirection.OUT),
            }, ports),
            **kwargs
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: GPSReceiverHigh(ports=ports, **kwargs),
            CyberAbstractionLevel.ALGORITHMIC: GPSReceiverAlgorithmic(ports=ports, **kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    @property
    def parameter_types(self):
        return {
            "signal_strength_threshold": float,
            "supported_protocols": list, # TODO: obviously make this better
        }
