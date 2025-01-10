from typing import Optional
from saci.modeling.device.component.component_base import Port, Ports, union_ports, PortDirection
from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication, UARTProtocol


class DebugHigh(CyberComponentHigh):
    __slots__ = ("supported_protocols", "communication", "protection")

    def __init__(self, communication=None, protection=None, **kwargs):
        super().__init__(**kwargs)
        self.communication = communication
        self.protection = protection

    @property
    def parameter_types(self):
        return {
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

    @property
    def parameter_types(self):
        return {
            "supported_protocols": list,
        }


class Debug(CyberComponentBase):

    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, ports: Optional[Ports]=None, **kwargs):
        super().__init__(
            ports=union_ports({
                "RF": Port(direction=PortDirection.INOUT),
                "Control": Port(direction=PortDirection.INOUT),
            }, ports),
            **kwargs
        )

        self.ABSTRACTIONS = {
            # TODO: ports?
            CyberAbstractionLevel.HIGH: DebugHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: DebugAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    @property
    def parameter_types(self):
        return {
            "supported_protocols": list,
        }
