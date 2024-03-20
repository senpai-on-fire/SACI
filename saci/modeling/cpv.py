from typing import List, Optional, Dict, Type

import networkx as nx

from . import Component


class CPV:
    def __init__(
        self,
        required_components: Optional[List[Type[Component]]] = None,
        observations: Optional[List[Component]] = None,
        transitions: Optional[Dict[Type[Component], nx.DiGraph]] = None
    ):
        self.required_components = required_components or []
        self.observations = observations or []
        self.transitions = transitions or {}