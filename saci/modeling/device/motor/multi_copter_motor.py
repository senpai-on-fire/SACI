from typing import List

from claripy import BVS

from ..component import ComponentAlgorithmic
from .multi_motor import MultiMotorHigh, MultiMotorAlgo


class MultiCopterMotorHigh(MultiMotorHigh):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class MultiCopterMotorAlgo(MultiMotorAlgo):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.v["lift"] = BVS("lift", 64)
        self.v["yaw"] = BVS("yaw", 64)
        self.v["pitch"] = BVS("pitch", 64)
