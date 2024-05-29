from .base_constrainer import BaseConstrainer
from ..modeling import ComponentBase


class BruteforceConstrainer(BaseConstrainer):
    def __init__(self):
        super().__init__()

    @classmethod
    def supports(cls, component: ComponentBase) -> bool:
        # the bruteforce constrainer supports everything
        return True

    def solve(self, component, output, out_state, behaviors, constraints):
        return True, {
            "behaviors": [],
            "input_state": None,
            "input": None,
            "constraints": [],
        }
