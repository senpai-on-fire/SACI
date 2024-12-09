from __future__ import annotations

from ..modeling.device import ComponentBase
from .behavior import Behaviors

# class CPVPath:
#     def __init__(self, path, behaviors):
#         self.path: list[ComponentBase] = path
#         self.final_behaviors: Behaviors = behaviors

#     def __repr__(self):
#         return f"<CPVPath: {repr(self.path)} -> {repr(self.final_behaviors)}>"

#     def to_json_dict(self) -> dict:
#         d = {
#             "path": self.path,
#             "final_behaviors": self.final_behaviors
#         }
#         return d


class CPVPath:
    def __init__(self, path, behaviors):
        self.path: list[ComponentBase] = path
        self.final_behaviors: Behaviors = behaviors

    def __repr__(self):
        return f"<CPVPath: {repr(self.path)} -> {repr(self.final_behaviors)}>"

    def to_json_dict(self) -> dict:
        # Convert `path` and `final_behaviors` to JSON-serializable forms
        return {
            "path": [comp.to_json_dict() for comp in self.path],
            "final_behaviors": self.final_behaviors.to_json_dict()
        }