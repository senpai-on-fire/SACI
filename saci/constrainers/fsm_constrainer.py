
from .base_constrainer import BaseConstrainer


class FSMConstrainer(BaseConstrainer):
    def solve(self, out_state, behaviors, constraints):
        return True, {
            "input": None,
            "input_state": None,
            "behaviors": None,
            "constraints": None,
        }
