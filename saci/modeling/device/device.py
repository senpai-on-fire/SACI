from typing import List, Type, Optional, Dict, Tuple

import networkx as nx

from .component import CyberComponentBase
from saci.modeling.device.component.cyber.cyber_abstraction_level import CYBER_ABSTRACTION_LEVELS
from ..state import GlobalState


class Device:
    def __init__(
        self,
        name: str,
        components: List[CyberComponentBase],
        component_graph: Dict[CyberComponentBase, nx.DiGraph] = None,
        node_maps: Dict[CyberComponentBase, Dict[CyberComponentBase, CyberComponentBase]] = None,
        edge_maps: Dict[CyberComponentBase, Dict[Tuple[CyberComponentBase, CyberComponentBase], Tuple[CyberComponentBase, CyberComponentBase]]] = None,
        state: Optional[GlobalState] = None,
    ):
        self.name = name
        self.components = components

        # communication and mappings between components
        self.component_graph = component_graph or nx.DiGraph()
        self.node_maps = node_maps or {
            lvl: {} for lvl in CYBER_ABSTRACTION_LEVELS
        }
        self.edge_maps = edge_maps or {
            lvl: {} for lvl in CYBER_ABSTRACTION_LEVELS
        }

        # state of the device (for Identifier)
        self.state = state

    def update_state(self, state: GlobalState) -> GlobalState:
        new_state: GlobalState = state.copy()
        for component in self.components:
            new_state = component.update_state(new_state)


