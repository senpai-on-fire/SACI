from collections.abc import Hashable
from dataclasses import dataclass
from typing import ClassVar, Generic, Union

import networkx as nx
from clorm import Predicate
from typing_extensions import TypeVar

from ..state import GlobalState
from .component import ComponentBase
from .componentid import ComponentID

# In the examples, and in manual reasoning, strings can be more convenient so as to be human-readable. But from the web
# frontend we'd like to use database primary keys. Thus this generic. Eventually we'll get rid of the weird ComponentID
# type alias we're using too, but I'm keeping it now for fewer changes.
CID = TypeVar("CID", bound=Hashable)


class Device(Generic[CID]):
    crash_atom: ClassVar[Predicate]
    description: ClassVar[str]
    name: str
    components: dict[CID, ComponentBase]
    component_graph: nx.DiGraph

    def __init__(
        self,
        name: str,
        components: list[ComponentBase] | dict[CID, ComponentBase],
        # communication and mappings between components
        component_graph: nx.DiGraph | None = None,
        state: GlobalState | None = None,
    ):
        self.name = name

        # TODO: remove all consumers of the list-based API. This shouldn't typecheck because you can make a Device[T]
        # have a components dict with ComponentID keys (where T != ComponentID)
        if isinstance(components, list):
            self.components = {ComponentID(str(id(c))): c for c in components}  # type: ignore
            # assume then that the component graph is also made of component objects
            if component_graph is not None:
                renamed_graph = nx.DiGraph()
                for comp, data in component_graph.nodes(data=True):
                    renamed_graph.add_node(str(id(comp)), **data)  # pyright: ignore
                for from_, to, data in component_graph.edges(data=True):  # pyright: ignore
                    renamed_graph.add_edge(str(id(from_)), str(id(to)), **data)  # pyright: ignore
                self.component_graph = renamed_graph
            else:
                self.component_graph = nx.DiGraph()
        else:
            self.components = components
            self.component_graph = component_graph or nx.DiGraph()

        # state of the device (for Identifier)
        self.state = state


@dataclass(frozen=True)
class IdentifiedComponent(Generic[CID]):
    id_: CID
    component: ComponentBase

    @classmethod
    def from_id(cls, device: Device[CID], comp_id: CID) -> "IdentifiedComponent[CID]":
        return cls(comp_id, device.components[comp_id])  # type: ignore


class DeviceFragment(Generic[CID]):
    def __init__(self, parent: Union[Device[CID], "DeviceFragment"], components: list[CID]):
        self.parent = parent
        self.components = components

    @property
    def component_graph(self):
        return self.parent.component_graph.subgraph(self.components)
