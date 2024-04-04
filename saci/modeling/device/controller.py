from .component import ComponentHigh


class ControllerHigh(ComponentHigh):
    __state_slots__ = ComponentHigh.__state_slots__ + ("emergency_state", )
    __slots__ = ComponentHigh.__slots__ + ("emergency_state", )

    def __init__(self, emergency_state=False, **kwargs):
        super().__init__(**kwargs)
        self.emergency_state = emergency_state
