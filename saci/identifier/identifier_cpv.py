import json
import os
import queue
from typing import List, Optional, Dict, Type, Any
from pathlib import Path

from saci.modeling import Device, CPV, ComponentBase
from saci.modeling.state import GlobalState
from saci.atoms import Atoms

def get_next_components(component: ComponentBase, components: List[ComponentBase], device: Device) -> List[ComponentBase]:
    graph = device.component_graph
    graph_neighbors = graph.out_edges(component)

    cpv_paths = []
    for start, end in graph_neighbors:
        if end in components:
            cpv_paths.append(end)
    return cpv_paths


class IdentifierCPV:
    def __init__(self, device: Device, initial_state: GlobalState):
        self.device = device
        self.initial_state = initial_state

    def identify(self, cpv: CPV) -> List[List[ComponentBase]]:

        # get the starting locations
        starting_locations = []
        for c in self.initial_state.components:
            if hasattr(c, 'has_external_input') and c.has_external_input:
                starting_locations.append(c)
        
        cpv_paths = []

        # CPV Path identification
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
        
        return cpv_paths

    def _parse_result(self, result):
        if result["Request Result"] == "Fail":
            for role in result['Tasks']:
                self.workers[role].input_queue.put(result['Tasks']['TA3'])
