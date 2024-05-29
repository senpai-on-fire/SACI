from ..modeling import ComponentBase


class BaseConstrainer:
    def __init__(self):
        pass

    @classmethod
    def supports(cls, component: ComponentBase) -> bool:
        raise NotImplementedError()

    def solve(self, component, output, out_state, behaviors, constraints):
        raise NotImplementedError()
