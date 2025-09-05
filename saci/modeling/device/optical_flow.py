from .component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class OpticalFlowSensorHigh(CyberComponentHigh):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class OpticalFlowSensorAlgorithmic(CyberComponentAlgorithmic):
    parameter_types = {
        "uses_corner_detection": bool,
    }


class OpticalFlowSensor(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "enabled")

    def __init__(self, enabled=True, **kwargs):
        super().__init__(**kwargs)
        self.enabled = enabled

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: OpticalFlowSensorHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: OpticalFlowSensorAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "uses_corner_detection": bool,
    }
