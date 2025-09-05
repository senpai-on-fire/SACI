from ..state.operation_mode import OperationMode
from .component import CyberAbstractionLevel, CyberComponentBase, CyberComponentHigh


class ControllerHigh(CyberComponentHigh):
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

    parameter_types = {
        # TODO: How do we know if the controller has integrity check?
        "has_integrity_check": bool,
    }


class Controller(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ControllerHigh(),
        }

    # TODO: dedup this with the abstracted version; perhaps this can happen automatically once we
    parameter_types = {
        # TODO: How do we know if the controller has integrity check?
        "has_integrity_check": bool,
    }
