from __future__ import annotations

from ..modeling.device import ComponentBase
from .behavior import Behaviors

class CPVPath:
    def __init__(self, path, behaviors):
        self.path: list[ComponentBase] = path
        self.final_behaviors: Behaviors = behaviors

    def __repr__(self):
        return f"<CPVPath: {repr(self.path)} -> {repr(self.final_behaviors)}>"

    def to_json_dict(self) -> dict:
        d = {
            "path": self.path,
            "final_behaviors": self.final_behaviors
        }
        return d
