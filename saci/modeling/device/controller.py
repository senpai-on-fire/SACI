from .component import ComponentBase, CyberComponentHigh, CyberAbstractionLevel, HardwareAbstractionLevel, HardwareHigh, CyberComponentHigh
from ..state.operation_mode import OperationMode


class ControllerCyberHigh(CyberComponentHigh):
    __state_slots__ = CyberComponentHigh.__state_slots__ + ("in_failsafe_mode", "operating_mode")
    __slots__ = CyberComponentHigh.__slots__ + ("in_failsafe_mode", "operating_mode")

    def __init__(self, in_failsafe_mode=False, operating_mode=OperationMode.MANUAL, **kwargs):
        """
        :param operating_mode, initialized to MANUAL mode
        :param in_failsafe_mode:
        :param kwargs:
        """
        super().__init__(**kwargs)
        # TODO: replace these once we have some concept of state variable
        self.operating_mode = operating_mode
        self.in_failsafe_mode = in_failsafe_mode

    @property
    def parameter_types(self):
        return {
            # TODO: How do we know if the controller has integrity check?
            "has_integrity_check": bool,
        }


class ControllerHardwareHigh(HardwareHigh):
    __state_slots__ = HardwareHigh.__state_slots__ + ("has_pwm_transmitter")
    __slots__ = HardwareHigh.__slots__ + ("has_pwm_transmitter")

    def __init__(self, has_pwm_transmitter=True, **kwargs):
        """
        :param has_pwm_transmitter:
        :param kwargs:
        """
        super().__init__(**kwargs)
        # TODO: replace these once we have some concept of state variable
        self.has_pwm_transmitter = has_pwm_transmitter

    @property
    def parameter_types(self):
        return {
            # TODO: How do we know if the controller has integrity check?
            "has_pwm_transmitter": bool,
        }


class Controller(ComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ControllerCyberHigh(),
            HardwareAbstractionLevel.HIGH: ControllerHardwareHigh(),
        }

    @property
    def parameter_types(self):
        # TODO: dedup this with the abstracted version; perhaps this can happen automatically once we 
        return {
            # TODO: How do we know if the controller has integrity check?
            "has_integrity_check": bool,
            "in_failsafe_mode ": bool,
            "has_pwm_transmitter": bool
        }