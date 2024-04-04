from saci.modeling.device.component import CyberComponentHigh, CyberComponentAlgorithmic

from claripy import BVS


class MotorHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class MotorAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.variables["rpm"] = BVS("rpm", 64)
