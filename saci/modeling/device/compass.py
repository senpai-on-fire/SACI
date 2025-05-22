from saci.modeling.device.component.component_base import Port, PortDirection
from .component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class CompassSensorHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class CompassSensorAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class CompassSensor(CyberComponentBase):
    __slots__ = "ABSTRACTIONS"

    def __init__(self, **kwargs):
        super().__init__(
            ports={
                "Magnetic Field": Port(direction=PortDirection.IN),
            },
            **kwargs,
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: CompassSensorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: CompassSensorAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
