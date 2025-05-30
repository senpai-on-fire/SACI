from saci.modeling.device.component.component_base import Port, PortDirection, union_ports
from .component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class CameraHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class Camera(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "powered")

    def __init__(self, powered=True, ports=None, **kwargs):
        super().__init__(
            ports=union_ports(
                {
                    "Field of View": Port(direction=PortDirection.IN),
                    "Output": Port(direction=PortDirection.OUT),
                },
                ports,
            ),
            **kwargs,
        )

        self.powered = powered

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: CameraHigh(),
            CyberAbstractionLevel.ALGORITHMIC: CyberComponentAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
