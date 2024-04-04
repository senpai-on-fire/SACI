from .component import ComponentHigh


class ControllerHigh(ComponentHigh):
    STATE_ATTR = ("emergency_state")
    def __init__(self,emergency_state=False, **kwargs):
        super().__init__(**kwargs)
        self.emergency_state = emergency_state