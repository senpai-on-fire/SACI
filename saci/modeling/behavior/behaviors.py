from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from .behavior import BehaviorBase


@dataclass(frozen=True)
class Behaviors:
    """
    Describes a list of behaviors.
    """

    behaviors: tuple[BehaviorBase, ...] = ()

    def __repr__(self):
        return f"Behaviors: {repr(self.behaviors)}"
