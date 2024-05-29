
from .base_constrainer import BaseConstrainer
from ..modeling import ComponentBase
from ..modeling.device import CyberComponentSourceCode


class CConstrainer(BaseConstrainer):
    @classmethod
    def supports(cls, component: ComponentBase) -> bool:
        return isinstance(component, CyberComponentSourceCode)  # TODO: also check if the programming language is C

    def solve(self, component, output, out_state, behaviors, constraints):
        return True, {
            "input": None,
            "input_state": None,
            "behaviors": None,
            "constraints": None,
        }
