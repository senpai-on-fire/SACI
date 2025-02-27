from copy import deepcopy
from dataclasses import dataclass

from saci.modeling.device.component.component_base import ComponentBase
from saci.modeling.device.device import ComponentID
from .modeling.device import Device, DeviceFragment

@dataclass(frozen=True)
class Assumption:
    """An element of a CPV hypothesis that makes a CPS more analyzable."""
    description: str

    def apply_to(self, device: Device):
        raise NotImplementedError()

    def transform(self, device: Device) -> Device:
        new_device = deepcopy(device)
        self.apply_to(new_device)
        return new_device

@dataclass(frozen=True)
class ParameterAssumption(Assumption):
    """Assumption that a parameter of a component has a certain value."""
    component_id: ComponentID
    parameter_name: str
    parameter_value: object

    def apply_to(self, device: Device):
        device.components[self.component_id].parameters[self.parameter_name] = self.parameter_value

@dataclass(frozen=True)
class RemoveComponentsAssumption(Assumption):
    """Assumption that certain components are not relevant to the hypothesis."""
    component_ids: frozenset[ComponentID]

    def apply_to(self, device: Device):
        for comp_id in self.component_ids:
            del device.components[comp_id]
            device.component_graph.remove_node(comp_id)

@dataclass(frozen=True)
class AddComponentAssumption(Assumption):
    """Assumption that a component not yet identified is present."""
    component_id: ComponentID
    component: ComponentBase

    def apply_to(self, device: Device):
        device.components[self.component_id] = self.component
        device.component_graph.add_node(self.component_id)

@dataclass(frozen=True)
class Hypothesis:
    """A guess at where a CPV may lie and at how to expose it."""
    description: str
    path: list[ComponentID]
    assumptions: list[Assumption]

    def apply_to(self, device: Device):
        for assm in self.assumptions:
            assm.apply_to(device)

    def transform(self, device: Device) -> Device:
        new_device = deepcopy(device)
        self.apply_to(new_device)
        return new_device
