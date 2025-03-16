from collections.abc import Hashable
from dataclasses import dataclass
from typing import Generic, Sequence, TypeVar
from copy import deepcopy

from saci.hypothesis import Hypothesis
from saci.modeling import Device, CPV, ComponentBase
from saci.modeling.device.device import IdentifiedComponent, ComponentID
from saci.modeling.state import GlobalState
from saci.modeling.vulnerability import BaseVulnerability


CID = TypeVar('CID', bound=Hashable)

def get_next_components(component_id: CID, device: Device[CID]) -> list[CID]:
    return list(device.component_graph.successors(component_id))

class IdentifierCPV(Generic[CID]):
    def __init__(
            self,
            device: Device[CID],
            initial_state: GlobalState[CID],
            vulns: Sequence[BaseVulnerability] | None = None,
    ):
        self.device = device
        self.initial_state = initial_state
        self.vulns = vulns or []

    def prepare_device(self) -> Device[CID]:
        device = deepcopy(self.device)
        # Apply any effects of vulnerabilities the device has
        for vuln in self.vulns:
            if vuln.exists(device):
                vuln.apply_effects(device)
        return device

    def check_hypothesis(self, cpv: CPV, hypothesis: Hypothesis[CID]) -> bool:
        device = self.prepare_device()
        hypothesis.apply_to(device)

        path = hypothesis.path
        if len(path) == 0:
            raise ValueError("Hypothesis's path should be nonempty")

        # Make sure we can actually enter the path in the first place!
        if not device.component_graph.nodes[path[0]].get("is_entry", False):
            return False

        return cpv.is_possible_path([device.components[comp_id] for comp_id in path])

    def identify(self, cpv: CPV) -> list[list[IdentifiedComponent[CID]]]:
        device = self.prepare_device()

        # Get the starting locations (components with external input)
        starting_locations: list[CID] = [
            c for c, is_entry in device.component_graph.nodes(data="is_entry", default=False) # type: ignore
            if is_entry
        ]

        cpv_paths: list[list[CID]] = []

        # CPV Path identification
        for start in starting_locations:
            stack = [(start, [start])]  # Stack stores (current_component, current_path)

            while stack:
                vertex, path = stack.pop()

                # Get the correct neighbors using the fixed function
                neighbors = get_next_components(vertex, device)

                for neighbor in neighbors:
                    if neighbor not in path:  # Avoid cycles in the current path
                        new_path = path + [neighbor]
                        stack.append((neighbor, new_path))

                # If the current path is valid, add it to the result
                if cpv.is_possible_path([device.components[comp_id] for comp_id in path]):
                    cpv_paths.append(path)

        return [[IdentifiedComponent.from_id(device, comp_id) for comp_id in path] for path in cpv_paths]
