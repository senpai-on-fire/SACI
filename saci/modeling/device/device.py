from typing import List, Type, Optional

import networkx as nx

from .component import ComponentBase
from ..state import GlobalState


class Device:
    def __init__(
        self,
        name: str,
        components: List[Type[ComponentBase]],
        high_graph: Optional[nx.DiGraph] = None,
        state: Optional[GlobalState] = None,
    ):
        self.name = name
        self.components = components
        self.component_graph = high_graph or nx.DiGraph()
        self.state = state
