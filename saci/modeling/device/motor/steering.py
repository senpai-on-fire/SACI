from .servo_motor import ServoHigh
from ..component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from ..component.cyber.cyber_abstraction_level import CyberAbstractionLevel


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
