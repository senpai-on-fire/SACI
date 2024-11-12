from typing import Optional

from .servo import ServoHigh, ServoAlgorithmic
from ..component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary

class Steering(CyberComponentBase):
    pass

class SteeringHigh(ServoHigh, Steering, CyberComponentHigh):
    """Describes a servo-based steering system for a vehicle.

    :param has_aps: Whether or not the steering system has an active protection system (APS) to prevent undesirable
        states. None means unknown.
    """
    __slots__ = ServoHigh.__slots__ + ("has_aps",)

    def __init__(self, has_aps: Optional[bool] = None, **kwargs):
        super().__init__(**kwargs)
        self.has_aps: Optional[bool] = has_aps
