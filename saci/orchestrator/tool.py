from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, TypeVar

from saci.modeling.device import ComponentBase
from saci.modeling.device.component import CyberAbstractionLevel, HardwareAbstractionLevel
from saci.modeling.device.componentid import ComponentID
from saci.modeling.device.control.controller import Controller
from saci.modeling.device.esc import ESC
from saci.modeling.device.interface.pwm_channel import PWMChannel
from saci.modeling.device.motor.motor import Motor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.device.sensor.compass import CompassSensor
from saci.modeling.device.sensor.gps import GPSReceiver
from saci_db.devices.ingested import Device

T = TypeVar('T', bound='ComponentSupported')

@dataclass(frozen=True)
class ComponentSupported:
    abstraction_levels: frozenset[CyberAbstractionLevel | HardwareAbstractionLevel]

    @classmethod
    def from_levels(cls: type[T], *levels: CyberAbstractionLevel | HardwareAbstractionLevel) -> T:
        return cls(abstraction_levels=frozenset(levels))

@dataclass(frozen=True)
class ComponentUnsupported:
    reason: str

class Tool(ABC):
    """Describes a sort of external tool SACI can orchestrate.

    This can be a modeling run, a co-simulation, a fuzzing run, or something else.
    """

    name: ClassVar[str]

    @property
    @abstractmethod
    def container_image(self) -> str:
        """The image URL/label for the container of this tool."""
        ...

    @abstractmethod
    def supports_component(self, component: ComponentBase) -> ComponentSupported | ComponentUnsupported:
        """Does this tool support the given component?

        Returns ComponentSupported with supported abstraction levels if so, or ComponentUnsupported with a reason why if
        not.

        """
        ...

    def supported_device_fragment(self, device: Device) -> frozenset[ComponentID]:
        return frozenset(comp_id for comp_id, comp in device.components.items() if self.supports_component(comp))

class SwabTool(Tool):
    """Tool specification for Swab."""

    name = "SWAB"

    @property
    def container_image(self) -> str:
        return "foo"

    def supports_component(self, component: ComponentBase) -> ComponentSupported | ComponentUnsupported:
        match component:
            case Controller():
                return ComponentSupported.from_levels(CyberAbstractionLevel.BINARY)
            case CompassSensor() | Steering() | ESC() | Motor() | PWMChannel():
                return ComponentSupported.from_levels(CyberAbstractionLevel.ALGORITHMIC)
            case _:
                return ComponentUnsupported(reason="unsupported component type")


TOOLS: list[Tool] = [
    SwabTool(),
]
