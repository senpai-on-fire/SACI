from ..component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentSourceCode,
)
from ..component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from .servo_motor import ServoHigh


class SteeringHigh(ServoHigh):
    """Describes a servo-based steering system for a vehicle.

    :param has_aps: Whether or not the steering system has an active protection system (APS) to prevent undesirable
        states. None means unknown.
    """

    parameter_types = {
        "has_aps": bool,
    }


class Steering(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: SteeringHigh(),
            CyberAbstractionLevel.ALGORITHMIC: CyberComponentAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "has_aps": bool,
    }
