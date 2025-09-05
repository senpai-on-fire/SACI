from saci.modeling.device.component.component_base import Port, PortDirection, Ports
from .component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication


class Telemetry(CyberComponentBase):
    """
    This is the base class for all telemetry components.
    """

    __slots__ = CyberComponentBase.__slots__ + ("ABSTRACTIONS",)

    def __init__(self, ports: Ports | None = None, **kwargs):
        if ports is None:
            ports = {
                "RF": Port(direction=PortDirection.INOUT),
                "Control": Port(direction=PortDirection.OUT),
                "Logging": Port(direction=PortDirection.IN),
            }
        super().__init__(ports=ports, **kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: TelemetryHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "protocol_name": str,
        "communication": BaseCommunication,
    }


class TelemetryHigh(CyberComponentHigh):
    parameter_types = {
        "protocol_name": str,
        "communication": BaseCommunication,
    }


class TelemetryAlgorithmic(CyberComponentAlgorithmic):
    def accepts_communication(self, communication: BaseCommunication) -> bool:
        return True
