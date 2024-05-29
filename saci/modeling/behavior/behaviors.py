from __future__ import annotations

from .behavior import BehaviorBase


class Behaviors:
    """
    Describes a list of behaviors.
    """

    def __init__(self, behaviors: list[BehaviorBase]):
        self.behaviors = behaviors or []

    def __repr__(self):
        return f"Behaviors: {repr(self.behaviors)}"
