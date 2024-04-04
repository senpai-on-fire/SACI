from saci.modeling.device.component import ComponentHigh, ComponentAlgorithmic

from claripy import BVS


class MotorHigh(ComponentHigh):
    __slots__ = ComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class MotorAlgorithmic(ComponentAlgorithmic):
    __slots__ = ComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.variables["rpm"] = BVS("rpm", 64)
