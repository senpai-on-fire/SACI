from collections.abc import Hashable
from dataclasses import dataclass
from typing import Literal, TypeVar

from pydantic import BaseModel

from saci.modeling.device import ComponentBase, Device, Controller, CompassSensor, Servo, ESC, PWMChannel, Motor


@dataclass(frozen=True)
class Container:
    image_name: str
    config_type: type[BaseModel]

CID = TypeVar('CID', bound=Hashable)

@dataclass(frozen=True)
class Tool:
    name: str
    containers: tuple[Container]
    compatible_comptypes: frozenset[type[ComponentBase]]

    def compatible_components(self, device: Device[CID]) -> list[CID]:
        return [
            comp_id
            for comp_id, comp
            in device.components.items()
            if any(isinstance(comp, comp_type) for comp_type in self.compatible_comptypes)
        ]

SwabFidelityLevel = Literal["High", "Medium", "Low"]

class SwabConfig(BaseModel):
    UI: Literal["server", "gui"]
    attack: Literal["emi", "stop", "tip"]
    compass: SwabFidelityLevel | None = None
    servo: SwabFidelityLevel | None = None
    motor: SwabFidelityLevel | None = None

swab_tool = Tool(
    name="SWAB",
    containers=(Container(
        "localswab",
        SwabConfig,
    ),),
    compatible_comptypes=frozenset([
        Controller,
        CompassSensor,
        Servo,
        ESC,
        PWMChannel,
        Motor,
    ]),
)

TOOLS: dict[str, Tool] = {
    "swab": swab_tool,
}
