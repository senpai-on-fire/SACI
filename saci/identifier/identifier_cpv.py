import json
import os
import queue
from typing import List, Optional, Dict, Type, Any
from pathlib import Path

from ..modeling import Device, CPV, ComponentBase
from ..modeling.state import GlobalState
from ..modeling.device.component import CyberComponentHigh
from ..orchestrator.workers import Worker

ATOM_FILE = os.path.join(Path(__file__).parent.parent.parent, "tests", "atoms.json")
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

    cpv_paths = []
    for start, end in graph_neighbors:
        if end in components:
            cpv_paths.append(end)
    return cpv_paths


class Identifier:
    def __init__(self, device: Device,
                 initial_state: GlobalState,
                 ta1: Worker = None,
                 ta2: Worker = None,
                 ta3: Worker = None,
                 queue = None):
        self.device = device
        self.initial_state = initial_state
        with open(ATOM_FILE, 'r') as f:
            self.atoms = json.load(f)
        self.ta1 = ta1
        self.ta2 = ta2
        self.ta3 = ta3
        self.queue = queue 
        self.workers = {"TA1": self.ta1,
                        "TA2": self.ta2,
                        "TA3": self.ta3}

    def identify(self, cpv: CPV) -> List[List[ComponentBase]]:
        # get the starting locations
        starting_locations = []
        for c in self.initial_state.components:
            if hasattr(c, 'has_external_input') and c.has_external_input:
                starting_locations.append(c)

        cpv_paths = []
        # check if the corresponding CPSVs exist
        if not cpv.vulnerable(self.device):
            return cpv_paths
        # DFS a path, then check the path against the CPV to see if it's possible
        for start in starting_locations:
            stack = [(start, [start])]
            visited = set()
            while stack:
                (vertex, path) = stack.pop()
                if vertex not in visited:
                    if cpv.is_possible_path(path):
                        cpv_paths.append(path)
                    else:
                        visited.add(vertex)
                        for neighbor in get_next_components(vertex, self.initial_state.components, self.device):
                            stack.append((neighbor, path + [neighbor]))
        
        # Ask TA2 to simulate the CPV, regarding the variables, if the CPV is a CPV hypothesis.
        if hasattr(cpv, "hypothesis"):
            description = self._check_atoms(cpv.hypothesis["Kinetic Effect"])
            if description is not None:
                self.ta2.input_queue.put(description)

                # We are waiting for TA2 to finish now
                # TODO we don't want to wait in the future
                result =  self.queue.get()

                # check the result
                self._parse_result(result)
                # while self._progressing() is False:
                    # break
        return cpv_paths

    def _parse_result(self, result):
        if result["Request Result"] == "Fail":
            for role in result['Tasks']:
                self.workers[role].input_queue.put(result['Tasks']['TA3'])

    def _check_atoms(self, effect):
        """
        check the atoms from self.atoms for what independent variables that TA2 should simulate
        """
        finder = list(filter(lambda x: x["Kinetic Effect"] == effect, self.atoms))
        if len(finder) > 0:
            return finder[0]
        return None

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
