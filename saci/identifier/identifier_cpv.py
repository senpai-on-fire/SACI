from saci.modeling import Device, CPV, ComponentBase
from saci.modeling.state import GlobalState

def get_next_components(component: ComponentBase, components: list[ComponentBase], device: Device) -> list[ComponentBase]:
    graph = device.component_graph
    
    # Get outgoing neighbors directly
    return [neighbor for neighbor in graph.successors(component) if neighbor in components]



class IdentifierCPV:
    def __init__(self, device: Device, initial_state: GlobalState):
        self.device = device
        self.initial_state = initial_state

    def identify(self, cpv: CPV) -> list[list[ComponentBase]]:
        # Get the starting locations (components with external input)
        starting_locations = [
            c for c, is_entry in self.device.component_graph.nodes(data="is_entry", default=False) # type: ignore
            if is_entry or c.has_external_input
        ]

        cpv_paths = []

        # CPV Path identification
        for start in starting_locations:
            stack = [(start, [start])]  # Stack stores (current_component, current_path)

            while stack:
                vertex, path = stack.pop()

                # Get the correct neighbors using the fixed function
                neighbors = get_next_components(vertex, self.device.components, self.device)

                for neighbor in neighbors:
                    if neighbor not in path:  # Avoid cycles in the current path
                        new_path = path + [neighbor]
                        stack.append((neighbor, new_path))

                # If the current path is valid, add it to the result
                if cpv.is_possible_path(path):
                    cpv_paths.append(path)

        return cpv_paths
