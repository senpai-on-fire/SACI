from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel

class DNNHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("known_source", "known_weight")

    def __init__(self, known_source=None, known_weight=None, **kwargs):
        super().__init__(**kwargs)
        self.known_source = known_source
        self.known_weight = known_weight


class DNNAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + ("known_source", "known_weight")

    def __init__(self, known_source=None, known_weight=None, **kwargs):
        super().__init__(**kwargs)
        self.known_source = known_source
        self.known_weight = known_weight


class DNN(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "has_external_input", "known_source", "known_weight")

    def __init__(self, has_external_input=False, known_source=None, known_weight=None, **kwargs):
        super().__init__(**kwargs)
        
        self.has_external_input = has_external_input
        self.known_source = known_source
        self.known_weight = known_weight

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: DNNHigh(known_source=known_source, known_weight=known_weight),
            CyberAbstractionLevel.ALGORITHMIC: DNNAlgorithmic(known_source=known_source, known_weight=known_weight),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }