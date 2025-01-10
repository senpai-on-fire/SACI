from typing import Optional

from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports
from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication



class Telemetry(CyberComponentBase):
    """
    This is the base class for all telemetry components.
    """

    __slots__ = CyberComponentBase.__slots__ + ("ABSTRACTIONS",)

    def __init__(self, ports: Optional[Ports]=None, **kwargs):
        super().__init__(
            ports=union_ports({
                "RF": Port(direction=PortDirection.INOUT),
                "Control": Port(direction=PortDirection.OUT),
                "Logging": Port(direction=PortDirection.IN),
            }, ports),
            **kwargs
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: TelemetryHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    @property
    def parameter_types(self):
        return {
            "protocol_name": str,
            "communication": BaseCommunication,
        }

class TelemetryHigh(CyberComponentHigh):
    @property
    def parameter_types(self):
        return {
            "protocol_name": str,
            "communication": BaseCommunication,
        }

class TelemetryAlgorithmic(CyberComponentAlgorithmic):
    def accepts_communication(self, communication: BaseCommunication) -> bool:
        return True

