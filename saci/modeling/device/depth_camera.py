from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel

from saci.modeling.device import CyberComponentBase

class DepthCamera(CyberComponentBase):
    __slots__ = ("supports_stereo_vision", "has_external_input", "enabled")

    def __init__(self, supports_stereo_vision=True, has_external_input=True, enabled=True, **kwargs):
        super().__init__(**kwargs)
        self.supports_stereo_vision = supports_stereo_vision
        self.has_external_input = has_external_input
        self.enabled = enabled

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: CyberComponentHigh(),
            CyberAbstractionLevel.ALGORITHMIC: CyberComponentAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }