from __future__ import annotations
from typing import Optional

from .behavior import BehaviorBase


class Behaviors:
    """
    Describes a list of behaviors.
    """

    def __init__(self, behaviors: Optional[list[BehaviorBase]]):
        self.behaviors = behaviors or []

    def __repr__(self):
        return f"Behaviors: {repr(self.behaviors)}"
