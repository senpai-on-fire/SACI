
from .base_constrainer import BaseConstrainer
from ..modeling import ComponentBase
from ..modeling.device import CyberComponentHigh


class ActuatorHighConstrainer(BaseConstrainer):
    @classmethod
    def supports(cls, component: ComponentBase) -> bool:
        return isinstance(component, CyberComponentHigh) and cls.is_supported_actuator(component.__class__.__name__)

    @staticmethod
    def is_supported_actuator(cls_name) -> bool:
        supported_actuator_keywords = {
            "motor",
        }
        return any(k in cls_name.lower() for k in supported_actuator_keywords)

    def solve(self, component, output, out_state, behaviors, constraints):
        return True, {
            "input": output,
            "input_state": None,
            "behaviors": None,
            "constraints": None,
        }
