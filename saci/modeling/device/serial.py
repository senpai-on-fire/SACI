from typing import Optional

from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports
from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication, UARTProtocol


class SerialHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("communication", "protection")

    def __init__(self, communication=None, protection=None, **kwargs):
        super().__init__(**kwargs)
        self.communication = communication
        self.protection = protection

    parameter_types = {
        "supported_protocols": bool,
    }


class SerialAlgorithmic(CyberComponentAlgorithmic):
    def accepts_communication(self, communication: BaseCommunication) -> bool:
        # TODO: depends on the protocol
        if any(isinstance(communication, protocol) for protocol in self.parameters["supported_protocols"]):
            return True
        # TODO: depends on the protocol
        else:
            return False

    parameter_types = {
        "supported_protocols": bool,
    }


class Serial(CyberComponentBase):
    def __init__(self, ports: Optional[Ports]=None, **kwargs):
        super().__init__(
            ports=union_ports({
                "Pins": Port(direction=PortDirection.INOUT),
                "Communication": Port(direction=PortDirection.INOUT),
            }, ports),
            **kwargs
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: SerialHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: SerialAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "supported_protocols": bool,
    }
