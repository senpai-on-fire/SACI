
from .base_constrainer import BaseConstrainer
from ..modeling import ComponentBase
from ..modeling.device import CyberComponentAlgorithmic


class FSMConstrainer(BaseConstrainer):
    @classmethod
    def supports(cls, component: ComponentBase) -> bool:
        return isinstance(component, CyberComponentAlgorithmic)  # TODO: Check if the component is an FSM component

    def solve(self, out_state, behaviors, constraints):
        return True, {
            "input": None,
            "input_state": None,
            "behaviors": None,
            "constraints": None,
        }
