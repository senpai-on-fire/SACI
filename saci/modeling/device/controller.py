from .component import CyberComponentHigh


class ControllerHigh(CyberComponentHigh):
    __state_slots__ = CyberComponentHigh.__state_slots__ + ("emergency_state",)
    __slots__ = CyberComponentHigh.__slots__ + ("emergency_state",)

    def __init__(self, emergency_state=False, **kwargs):
        super().__init__(**kwargs)
        self.emergency_state = emergency_state
