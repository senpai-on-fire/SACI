from dataclasses import dataclass
from typing import ClassVar, List, NewType, Type, Optional, Dict, Tuple, TypeVar, Union

import networkx as nx
from clorm import Predicate

from .component import ComponentBase
from saci.modeling.device.component.cyber.cyber_abstraction_level import CYBER_ABSTRACTION_LEVELS
from .componentid import ComponentID
from ..state import GlobalState


class Device:
    crash_atom: ClassVar[Predicate]
    description: ClassVar[str]

    def __init__(
        self,
        name: str,
        components: list[ComponentBase] | dict[ComponentID, ComponentBase],
        # communication and mappings between components
        component_graph: Optional[nx.DiGraph] = None,
        state: Optional[GlobalState] = None,
    ):
        self.name = name

        if isinstance(components, list):
            self.components = {ComponentID(str(id(c))): c for c in components}
            # assume then that the component graph is also made of component objects
            if component_graph is not None:
                renamed_graph = nx.DiGraph()
                for comp, data in component_graph.nodes(data=True):
                    renamed_graph.add_node(str(id(comp)), **data) # pyright: ignore
                for from_, to, data in component_graph.edges(data=True): # pyright: ignore
                    renamed_graph.add_edge(str(id(from_)), str(id(to)), **data) # pyright: ignore
                self.component_graph = renamed_graph
            else:
                self.component_graph = nx.DiGraph()
        else:
            self.components = components
            self.component_graph = component_graph or nx.DiGraph()

        # state of the device (for Identifier)
        self.state = state

T = TypeVar('T', bound='IdentifiedComponent')

@dataclass(frozen=True)
class IdentifiedComponent:
    id_: ComponentID
    component: ComponentBase

    @classmethod
    def from_id(cls: type[T], device: Device, comp_id: ComponentID) -> 'IdentifiedComponent':
        return cls(comp_id, device.components[comp_id])

class DeviceFragment:
    def __init__(self, parent: Union[Device, "DeviceFragment"], components: list[ComponentID]):
        self.parent = parent
        self.components = components

    @property
    def component_graph(self):
        return self.parent.component_graph.subgraph(self.components)
