from typing import Optional

from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports
from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication


class WifiHigh(CyberComponentHigh):
    __slots__ = ("communication",)

    def __init__(self, communication=None, **kwargs):
        super().__init__(**kwargs)
        self.communication = communication

    @property
    def parameter_types(self):
        return {
            "supported_protocols": list,
            "protection": str,
            "encryption_type": str,
        }

class WifiAlgorithmic(CyberComponentAlgorithmic):

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

class Wifi(CyberComponentBase):
    """
    This is the base class for all telemetry components.
    """

    def __init__(self, ports: Optional[Ports]=None, **kwargs):
        super().__init__(
            ports=union_ports({
                "RF": Port(direction=PortDirection.INOUT),
                "Networking": Port(direction=PortDirection.INOUT),
            }, ports),
            **kwargs
        )

        self.ABSTRACTIONS = {
            # TODO: ports for abstractions?
            CyberAbstractionLevel.HIGH: WifiHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: WifiAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    @property
    def parameter_types(self):
        return {
            "supported_protocols": list,
            "protection": str,
            "encryption_type": str,
        }
