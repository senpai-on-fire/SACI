from .component import CyberComponentHigh, CyberComponentBase, CyberAbstractionLevel


class ControllerHigh(CyberComponentHigh):
    __state_slots__ = CyberComponentHigh.__state_slots__ + ("in_failsafe_mode",)
    __slots__ = CyberComponentHigh.__slots__ + ("in_failsafe_mode",)

    def __init__(self, in_failsafe_mode=False, integrity_check=False, **kwargs):
        """


        :param in_failsafe_mode:
        :param kwargs:
        """
        super().__init__(**kwargs)
        self.in_failsafe_mode = in_failsafe_mode
        self.integrity_check = integrity_check


class Controller(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ControllerHigh(),
        }
