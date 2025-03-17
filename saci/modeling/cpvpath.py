from __future__ import annotations
from dataclasses import dataclass

from ..modeling.device import IdentifiedComponent
from .behavior import Behaviors


@dataclass(frozen=True)
class CPVPath:
    path: tuple[IdentifiedComponent, ...]
    final_behaviors: Behaviors

    def __repr__(self):
        return f"<CPVPath: {repr(self.path)} -> {repr(self.final_behaviors)}>"
