from typing import List

from claripy import BVS

from ..component import ComponentAlgorithmic
from .motor import MotorHigh, MotorAlgorithmic


class MultiMotorHigh(MotorHigh):
    __slots__ = MotorHigh.__slots__ + ("motors",)

    def __init__(self, motors=None, **kwargs):
        super().__init__(**kwargs)
        self.motors: List[MotorHigh] = motors or []

    @property
    def motor_cnt(self):
        return len(self.motors)


class MultiMotorAlgo(MotorAlgorithmic):
    __slots__ = MotorAlgorithmic.__slots__ + ("motors",)

    def __init__(self, motors=None, **kwargs):
        super().__init__(**kwargs)
        self.motors: List[MotorAlgorithmic] = motors or []

        self.v["rpm"] = self.rpm

    @property
    def rpm(self):
        total_rpm = BVS("rpm", 64)
        for motor in self.motors:
            total_rpm += motor.v["rpm"]

        return total_rpm
