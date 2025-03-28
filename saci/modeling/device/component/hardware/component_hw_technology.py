from typing import Optional


from saci.modeling.device.component.hardware.hardware_component_base import HardwareComponentBase
from saci.modeling.device.component.hardware.hardware_abstraction_level import HardwareAbstractionLevel

import claripy


class HardwareTechnology(HardwareComponentBase):
    __state_slots__ = HardwareComponentBase.__state_slots__ + ("reading",)
    __slots__ = HardwareComponentBase.__slots__ + (
        "technology",
        "reading",
    )

    def __init__(
        self,
        abstraction=HardwareAbstractionLevel.TECHNOLOGY,
        technology: Optional[str] = None,
        readings: Optional[dict[str, claripy.ast.bv.BV]] = None,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.reading = readings or {}
        self.technology = technology

    @property
    def tech(self):
        return self.technology
