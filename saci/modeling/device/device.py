from typing import List, Type, Optional, Dict, Tuple

import networkx as nx

from .component import CyberComponentBase
from .component.cyber_abstraction_level import ABSTRACTION_LEVELS
from ..state import GlobalState


class Device:
    def __init__(
        self,
        name: str,
        components: List[Type[CyberComponentBase]],
        component_graphs: Dict[Type[CyberComponentBase], nx.DiGraph] = None,
        node_maps: Dict[Type[CyberComponentBase], Dict[CyberComponentBase, CyberComponentBase]] = None,
        edge_maps: Dict[Type[CyberComponentBase], Dict[Tuple[CyberComponentBase, CyberComponentBase], Tuple[CyberComponentBase, CyberComponentBase]]] = None,
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

    def update_state(self, state: GlobalState) -> GlobalState:
        new_state: GlobalState = state.copy()
        for component in self.components:
            new_state = component.update_state(new_state)


