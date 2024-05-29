
from .base_constrainer import BaseConstrainer
from ..modeling import ComponentBase
from ..modeling.device import CyberComponentBinary


class BinaryConstrainer(BaseConstrainer):
    @classmethod
    def supports(cls, component: ComponentBase) -> bool:
        return isinstance(component, CyberComponentBinary)

    def solve(self, component, output, out_state, behaviors, constraints):
        return True, {
            "input": None,
            "input_state": None,
            "behaviors": None,
            "constraints": None,
        }
