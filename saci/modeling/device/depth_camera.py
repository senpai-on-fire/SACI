from saci.modeling.device.component.component_base import Port, PortDirection, Ports

from .component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class DepthCameraHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class DepthCameraAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class DepthCamera(CyberComponentBase):
    __slots__ = ("enabled", "ABSTRACTIONS")

    def __init__(self, ports: Ports | None = None, enabled=True, **kwargs):
        if ports is None:
            ports = {
                "Field of View": Port(direction=PortDirection.IN),
            }
        super().__init__(ports=ports, **kwargs)

        # TODO: once we support some sort of state variables replace this
        self.enabled = enabled

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: CyberComponentHigh(),
            CyberAbstractionLevel.ALGORITHMIC: CyberComponentAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "supports_stereo_vision": bool,
    }
