from claripy import BVS

from ..component import CyberComponentBase, CyberAbstractionLevel
from .multi_motor import MultiMotorHigh, MultiMotorAlgo

# TODO: Is rover motor single or multi motor?

class RoverMotorHigh(MultiMotorHigh):
    __slots__ = MultiMotorHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class RoverMotorAlgo(MultiMotorAlgo):
    __slots__ = MultiMotorAlgo.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.v["x"] = BVS("x", 64)
        self.v["y"] = BVS("y", 64)


class RoverMotor(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: RoverMotorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: RoverMotorAlgo(),
        }
