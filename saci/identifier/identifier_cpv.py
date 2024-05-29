from typing import List, Optional, Dict, Type, Any

from ..modeling import Device, CPV, ComponentBase
from ..modeling.state import GlobalState
from ..modeling.device.component import CyberComponentHigh

# from clorm import Predicate, ConstantStr, SimpleField
# from clorm.clingo import Control

# # TODO: This should go in another package or something
# # Solver data model
# class StateVariable(Predicate):
#     time: int
#     name: ConstantStr
#     value: SimpleField

# class Component(Predicate):
#     name: str

# class ComponentEdge(Predicate):
#     src: Component
#     dst: Component

# class ComponentPath(Predicate):
#     time: int
#     src: Component
#     dst: Component

# class GoalFound(Predicate):
#     time: int

def get_next_components(component: ComponentBase, components: List[ComponentBase], device: Device) -> List[ComponentBase]:
    graph = device.component_graph
    graph_neighbors = graph.out_edges(component)

    to_return = []
    for start, end in graph_neighbors:
        if end in components:
            to_return.append(end)
    return to_return


class Identifier:
    def __init__(self, device: Device, initial_state: GlobalState):
        self.device = device
        self.initial_state = initial_state


    def identify(self, cpv: CPV) -> List[List[ComponentBase]]:
        # get the starting locations
        starting_locations = []
        for c in self.initial_state.components:
            if hasattr(c, 'has_external_input') and c.has_external_input:
                starting_locations.append(c)


        to_return = []
        # DFS a path, then check the path against the CPV to see if it's possible
        for start in starting_locations:
            stack = [(start, [start])]
            visited = set()
            while stack:
                (vertex, path) = stack.pop()
                if vertex not in visited:
                    if cpv.is_possible_path(path):
                        to_return.append(path)
                    else:
                        visited.add(vertex)
                        for neighbor in get_next_components(vertex, self.initial_state.components, self.device):
                            stack.append((neighbor, path + [neighbor]))
        return to_return


    def in_progress_asp_identify(self) -> Dict[Type[CPV], List[Type[ComponentBase]]]:
        # Turn the communication graph into clingo stuff
        ctl = Control(unifier=[StateVariable, Component, ComponentEdge, ComponentPath, GoalFound])

        facts = []
        component_map = {}
        for component in self.device.components:
            c = Component(component.__name__)
            component_map[component.__name__] = c
            facts.append(c)

        for level, graph in self.device.component_graphs.items():
            for _from, _to in graph.edges():
                from_component = component_map[_from.__name__]
                to_component = component_map[_to.__name__]
                edge = ComponentEdge(from_component, to_component)

        ctl.load("identifier.lp")

        ctl.ground([("base", [])])
        with ctl.solve(yield_=True) as handle:
            for model in handle:
                import ipdb; ipdb.set_trace()
        return {}
