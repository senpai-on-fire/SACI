
class BaseConstrainer:
    def __init__(self):
        pass

    def solve(self, out_state, behaviors, constraints):
        raise NotImplementedError()
