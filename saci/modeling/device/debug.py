from typing import Optional
from saci.modeling.device.component.component_base import Port, Ports, PortDirection
from .component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication


class DebugHigh(CyberComponentHigh):
    __slots__ = ("supported_protocols", "communication", "protection")

    def __init__(self, communication=None, protection=None, **kwargs):
        super().__init__(**kwargs)
        self.communication = communication
        self.protection = protection

    parameter_types = {
        "supported_protocols": list,
    }


class DebugAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + ("supported_protocols",)

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        # TODO: depends on the protocol
        if any(isinstance(communication, protocol) for protocol in self.parameters["supported_protocols"]):
            return True
        # TODO: depends on the protocol
        else:
            return False

    parameter_types = {
        "supported_protocols": list,
    }


class Debug(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, ports: Optional[Ports] = None, **kwargs):
        if ports is None:
            ports = {
                "RF": Port(direction=PortDirection.INOUT),
                "Control": Port(direction=PortDirection.INOUT),
            }
        super().__init__(ports=ports, **kwargs)

        self.ABSTRACTIONS = {
            # TODO: ports?
            CyberAbstractionLevel.HIGH: DebugHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: DebugAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "supported_protocols": list,
    }
