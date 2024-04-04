from typing import List, Dict


from .component_base import ComponentBase
from .hardware_abstraction_level import HardwareAbstractionLevel

import claripy


class HardwareTechnology(ComponentBase):
    ComponentBase.__state_slots__ = ComponentBase.__state_slots__ + ("reading", )
    ComponentBase.__slots__ = ComponentBase.__slots__ + ("technology", "reading",)

    def __init__(
        self,
        abstraction=HardwareAbstractionLevel.TECHNOLOGY,
        technology: str = None,
        readings: Dict[str, claripy.ast.bv.BV] = None,
        **kwargs
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.reading = readings or {}
        self.technology = technology

    @property
    def tech(self):
        return self.technology
