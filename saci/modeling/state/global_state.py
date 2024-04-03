from typing import List

from ..device import ComponentBase


class GlobalState:
    def __init__(self, components: List[ComponentBase], time=0):
        self.components = components
        self.time = time

    def copy(self):
        return GlobalState(components=[comp.copy() for comp in self.components], time=self.time)
