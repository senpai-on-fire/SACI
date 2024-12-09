from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel

class DepthCameraHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(has_external_input=True, **kwargs)

class DepthCameraAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class DepthCamera(CyberComponentBase):
    __slots__ = ("supports_stereo_vision", "has_external_input", "enabled", "ABSTRACTIONS")

    def __init__(self, supports_stereo_vision=True, has_external_input=True, enabled=True, **kwargs):
        super().__init__(**kwargs)

        self.has_external_input = has_external_input
        self.supports_stereo_vision = supports_stereo_vision
        self.enabled = enabled

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: CyberComponentHigh(),
            CyberAbstractionLevel.ALGORITHMIC: CyberComponentAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }