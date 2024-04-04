from typing import List

from claripy import BVS

from ..component import CyberComponentAlgorithmic
from .multi_motor import MultiMotorHigh, MultiMotorAlgo


class MultiCopterMotorHigh(MultiMotorHigh):
    __slots__ = MultiMotorHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class MultiCopterMotorAlgo(MultiMotorAlgo):
    __slots__ = MultiMotorAlgo.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.v["lift"] = BVS("lift", 64)
        self.v["yaw"] = BVS("yaw", 64)
        self.v["pitch"] = BVS("pitch", 64)
