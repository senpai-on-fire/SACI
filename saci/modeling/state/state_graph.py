from typing import List, Optional

import networkx as nx

from .state_node import StateNode
from .state_transition import StateTransition


class StateGraph:
    def __init__(self, state_graph: nx.DiGraph, current_state=None):
        self.state_graph = state_graph
        self.current_state: Optional[StateNode] = current_state

        self.states: List[StateNode] = list(self.state_graph.nodes)
        self.transitions: List[StateTransition] = list(self.state_graph.edges)
