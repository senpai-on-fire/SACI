from typing import List, Type, Optional, Dict

import networkx as nx

from .component import ComponentBase
from .component.cyber_abstraction_level import ABSTRACTION_LEVELS
from ..state import GlobalState


class Device:
    STATE_ATTR = ("state", )

    def __init__(
        self,
        name: str,
        components: List[Type[ComponentBase]],
        component_graphs: Dict[Type[ComponentBase], nx.DiGraph] = None,
        state: Optional[GlobalState] = None,
    ):
        # description of the device
        self.name = name
        self.components = components
        self.component_graphs = component_graphs or {
            lvl: nx.DiGraph() for lvl in ABSTRACTION_LEVELS
        }

        # state of the device
        self.state = state
