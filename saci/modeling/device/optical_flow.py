from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication

class OpticalFlowSensorHigh(CyberComponentHigh):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class OpticalFlowSensorAlgorithmic(CyberComponentAlgorithmic):
    @property
    def parameter_types(self):
        return {
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

    @property
    def parameter_types(self):
        return {
            "uses_corner_detection": bool,
        }
