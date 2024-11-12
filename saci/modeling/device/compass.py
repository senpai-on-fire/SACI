from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class CompassSensorHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(has_external_input=True, **kwargs)

class CompassSensorAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class CompassSensor(CyberComponentBase):
    __slots__ = ("has_external_input", "ABSTRACTIONS")

    def __init__(self, has_external_input=False, **kwargs):
        super().__init__(**kwargs)

        self.has_external_input = has_external_input

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: CompassSensorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: CompassSensorAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
