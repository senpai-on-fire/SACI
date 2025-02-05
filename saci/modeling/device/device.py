from typing import List, Type, Optional, Dict, Tuple

import networkx as nx
from clorm import Predicate

from .component import ComponentBase
from saci.modeling.device.component.cyber.cyber_abstraction_level import CYBER_ABSTRACTION_LEVELS
from ..state import GlobalState


class Device:
    crash_atom: Predicate
    description: str

    def __init__(
        self,
        name: str,
        components: List[ComponentBase],
        component_graph: Optional[nx.DiGraph] = None,
        state: Optional[GlobalState] = None,
        options: tuple[str, ...] = (),
    ):
        self.name = name
        self.components = components

        # communication and mappings between components
        self.component_graph = component_graph or nx.DiGraph()

        # state of the device (for Identifier)
        self.state = state

        self.options = options

    def add_component(self, component):
        self.components.append(component)

    def get_option(self, name):
        return None

    def set_option(self, name, value):
        pass
