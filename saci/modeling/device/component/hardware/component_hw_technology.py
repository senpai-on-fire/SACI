import claripy

from saci.modeling.device.component.hardware.hardware_abstraction_level import HardwareAbstractionLevel
from saci.modeling.device.component.hardware.hardware_component_base import HardwareComponentBase


class HardwareTechnology(HardwareComponentBase):
    __state_slots__ = HardwareComponentBase.__state_slots__ + ("reading",)
    __slots__ = HardwareComponentBase.__slots__ + (
        "technology",
        "reading",
    )

    def __init__(
        self,
        abstraction=HardwareAbstractionLevel.TECHNOLOGY,
        technology: str | None = None,
        readings: dict[str, claripy.ast.bv.BV] | None = None,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.reading = readings or {}
        self.technology = technology

    @property
    def tech(self):
        return self.technology
