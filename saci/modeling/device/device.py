from typing import List, Type, Optional, Dict, Tuple

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
        node_maps: Dict[Type[ComponentBase], Dict[ComponentBase, ComponentBase]] = None,
        edge_maps: Dict[Type[ComponentBase], Dict[Tuple[ComponentBase, ComponentBase], Tuple[ComponentBase, ComponentBase]]] = None,
        state: Optional[GlobalState] = None,
    ):
        self.name = name
        self.components = components

        # communication and mappings between components
        self.component_graphs = component_graphs or {
            lvl: nx.DiGraph() for lvl in ABSTRACTION_LEVELS
        }
        self.node_maps = node_maps or {
            lvl: {} for lvl in ABSTRACTION_LEVELS
        }
        self.edge_maps = edge_maps or {
            lvl: {} for lvl in ABSTRACTION_LEVELS
        }

        # state of the device (for Identifier)
        self.state = state
