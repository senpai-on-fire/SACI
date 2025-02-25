from typing import List

from ..device.componentid import ComponentID
from ..device import ComponentBase


class GlobalState:
    def __init__(self, components: dict[ComponentID, ComponentBase], time=0):
        self.components = components
        self.time = time

    def copy(self):
        return GlobalState(
            components={comp_id: comp.copy() for comp_id, comp in self.components.items()},
            time=self.time
        )
