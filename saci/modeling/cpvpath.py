from typing import List

from ..modeling.device import ComponentBase
from .behavior import Behaviors

class CPVPath:
    def __init__(self, path, behaviors):
        self.path: List[ComponentBase] = path
        self.final_behaviors: Behaviors = behaviors

    def __repr__(self):
        return f"<CPVPath: {repr(self.path)} -> {repr(self.final_behaviors)}>"
