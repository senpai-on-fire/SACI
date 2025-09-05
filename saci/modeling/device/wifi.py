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


class WifiHigh(CyberComponentHigh):
    __slots__ = ("communication",)

    def __init__(self, communication=None, **kwargs):
        super().__init__(**kwargs)
        self.communication = communication

    parameter_types = {
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

    parameter_types = {
        "supported_protocols": list,
    }


class Wifi(CyberComponentBase):
    """
    This is the base class for all telemetry components.
    """

    def __init__(self, ports: Ports | None = None, **kwargs):
        if ports is None:
            ports = {
                "RF": Port(direction=PortDirection.INOUT),
                "Networking": Port(direction=PortDirection.INOUT),
            }
        super().__init__(
            ports=ports,
            **kwargs,
        )

        self.ABSTRACTIONS = {
            # TODO: ports for abstractions?
            CyberAbstractionLevel.HIGH: WifiHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: WifiAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "supported_protocols": list,
        "protection": str,
        "encryption_type": str,
    }
