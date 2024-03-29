from saci.modeling.device.component import ComponentHigh, ComponentAlgorithmic

from claripy import BVS


class MotorHigh(ComponentHigh):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class MotorAlgorithmic(ComponentAlgorithmic):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.variables["rpm"] = BVS("rpm", 64)
