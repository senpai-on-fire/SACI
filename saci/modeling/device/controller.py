from .component import CyberComponentHigh, CyberComponentBase, CyberAbstractionLevel


class ControllerHigh(CyberComponentHigh):
    __state_slots__ = CyberComponentHigh.__state_slots__ + ("in_failsafe_mode", "has_integrity_check", "operating_mode")
    __slots__ = CyberComponentHigh.__slots__ + ("in_failsafe_mode", "has_integrity_check", "operating_mode")

    def __init__(self, in_failsafe_mode=False, has_integrity_check=False, operating_mode=None, **kwargs):
        """


        :param operating_mode
        :param in_failsafe_mode:
        :param has_integrity_check:
        :param kwargs:
        """
        super().__init__(**kwargs)
        self.operating_mode = operating_mode
        self.in_failsafe_mode = in_failsafe_mode
        self.has_integrity_check = has_integrity_check


class Controller(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ControllerHigh(),
        }
