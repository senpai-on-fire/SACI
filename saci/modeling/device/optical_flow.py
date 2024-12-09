from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication

class OpticalFlowSensorHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__
    
    def __init__(self, **kwargs):
        super().__init__(has_external_input=True, **kwargs)


class OpticalFlowSensorAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + ('uses_corner_detection',)

    def __init__(self, uses_corner_detection=True, **kwargs):
        super().__init__(**kwargs)
        
        self.uses_corner_detection = uses_corner_detection


class OpticalFlowSensor(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "has_external_input", "uses_corner_detection", "enabled")

    def __init__(self, has_external_input=True, uses_corner_detection=True, enabled=True, **kwargs):
        super().__init__(**kwargs)
        
        self.has_external_input = has_external_input
        self.uses_corner_detection = uses_corner_detection
        self.enabled = enabled

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: OpticalFlowSensorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: OpticalFlowSensorAlgorithmic(uses_corner_detection=uses_corner_detection),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }