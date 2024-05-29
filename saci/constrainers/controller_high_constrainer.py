
from .base_constrainer import BaseConstrainer
from ..modeling import ComponentBase
from ..modeling.device import CyberComponentHigh


class ControllerHighConstrainer(BaseConstrainer):
    @classmethod
    def supports(cls, component: ComponentBase) -> bool:
        return isinstance(component, CyberComponentHigh) and cls.is_supported_controller(component.__class__.__name__)

    @staticmethod
    def is_supported_controller(cls_name) -> bool:
        supported_actuator_keywords = {
            "controller",
        }
        return any(k in cls_name.lower() for k in supported_actuator_keywords)

    def solve(self, component, output, out_state, behaviors, constraints):
        return True, {
            "input": {"manual_mavlink_command": "SHUTDOWN"},
            "input_state": None,
            "behaviors": None,
            "constraints": None,
        }
