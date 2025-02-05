from __future__ import annotations

from ..modeling.device import ComponentBase
from .behavior import Behaviors


class CPVPath:
    def __init__(self, path, behaviors):
        self.path: list[ComponentBase] = path
        self.final_behaviors: Behaviors = behaviors
        self.cpv_inputs = []

    def __repr__(self):
        return f"<CPVPath: {repr(self.path)} -> {repr(self.final_behaviors)}>"
