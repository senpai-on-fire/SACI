from typing import Optional

from ..state import StateGraph


class Component:
    def __init__(self, name=None, is_powered=True, receives_external_signals=False):
        # other properties
        self.name = name

        # state characteristics
        self.is_powered = is_powered
        self.state_graph: Optional[StateGraph] = None

        # behavior characteristics (unchangeable in runtime)
        self.receives_external_signals = receives_external_signals

