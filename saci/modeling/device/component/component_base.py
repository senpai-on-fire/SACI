from dataclasses import dataclass
import sys
from enum import Enum

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    class StrEnum(str, Enum):
        pass
from typing import Any, Type, TypeAlias  # noqa: UP035

from saci.modeling.capability import Capability


class PortDirection(StrEnum):
    IN = "in"
    OUT = "out"
    INOUT = "inout"


@dataclass(frozen=True)
class Port:
    """Description of a port on a component."""

    direction: PortDirection | None
    """Dataflow direction of the port, with respect to the component this port is part of."""

    # TODO: abstraction level, units, etc


Ports: TypeAlias = dict[str, Port]


def union_ports(ports1: Ports | None, ports2: Ports | None) -> Ports | None:
    # TODO: some other strategy for duplicate keys besides rejection?
    # TODO: handle arbitrary number of dicts?
    if not ports1:
        return ports2
    if not ports2:
        return ports1
    if set(ports1.keys()) & set(ports2.keys()):
        raise ValueError("ports dictionaries have overlapping keys")
    return ports1 | ports2


class ComponentBase:
    """A ComponentBase is the base class for all components in the system. A component, at a high-level, is any device
    in the full system that can interface with at least one other device, whether at a dataflow level or a physical
    level.

    Components have `parameters`, which are time-invariant properties of the component that affect its behavior for
    analysis, modeling, and simulation purposes. Examples include the weight of a chassis and a firmware file for a
    microcontroller. The parameters expected and their types should be given as the `parameter_types` property. Not
    all the parameters have to be supplied, in order to allow refining the modeling over time or test different
    assumptions for parameter values.

    TODO regarding parameters:
     - a way for components to tell which parameters are needed for a given type of simulation/analysis or
       abstraction level
     - default parameter values, or a default distribution of parameter values to sample from to check robustness
       when modeling with incomplete information
     - replace the current dict-based parameter_types/parameters with something class-based

    Components also have `ports`, which are points of connection to other components. These can be used to signify
    physical, electrical, or other types of connections with data flow.

    TODO regarding ports:
     - ways to indicate whether a connection between two ports is valid at a given abstraction level and, if not, how
       to make it valid
     - different representations of the same ports (as in the Blueprint format), to eventually use for different
       abstraction levels/simulation types
    """

    __state_slots__ = ()
    __slots__ = ("name", "type", "parameters", "ports", "capabilities")

    def __init__(
        self,
        name: str | None = None,
        _type=None,
        parameters: dict[str, Any] | None = None,
        ports: dict[str, Port] | None = None,
        capabilities: set[tuple[Capability, str | None]] | None = None,
    ):
        self.name = name or self.__class__.__name__
        self.type = _type
        self.parameters = parameters or {}
        self.ports = ports or {"Default": Port(direction=None)}
        self.capabilities = capabilities or set()

    def __repr__(self):
        type_name = type(self).__name__
        if self.name != type_name:
            return f"{self.name} ({type_name})"
        else:
            return self.name

    parameter_types: dict[str, Type] = {}  # noqa: UP006

    def check_parameter_types(self):
        for param_name, param_value in self.parameters.items():
            if (param_type := self.parameter_types.get(param_name)) is None:
                raise ValueError(f"parameter {param_name!r} has not been declared")
            elif not isinstance(param_value, param_type):
                raise ValueError(f"parameter {param_name!r} with value {param_value!r} is not of type {param_type}")

    @property
    def has_external_input(self) -> bool:
        # TODO: remove this, this is just a temporary hack while other code still depend on has_external_input
        return any(port.direction in (PortDirection.IN, PortDirection.INOUT) for port in self.ports.values())
