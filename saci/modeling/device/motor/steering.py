from typing import Optional

from .servo_motor import ServoHigh, ServoAlgorithmic
from ..component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from ..component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class SteeringHigh(ServoHigh, CyberComponentHigh):
    """Describes a servo-based steering system for a vehicle.

    :param has_aps: Whether or not the steering system has an active protection system (APS) to prevent undesirable
        states. None means unknown.
    """
    __slots__ = ServoHigh.__slots__ + ("has_aps",)

    def __init__(self, has_aps: Optional[bool] = None, **kwargs):
        super().__init__(**kwargs)
        self.has_aps: Optional[bool] = has_aps


class Steering(CyberComponentBase):
    __slots__ = ("has_external_input", "ABSTRACTIONS")

    def __init__(self, has_external_input=False, **kwargs):
        super().__init__(**kwargs)

        self.has_external_input = has_external_input

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: SteeringHigh(),
            CyberAbstractionLevel.ALGORITHMIC: CyberComponentAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

