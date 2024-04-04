from typing import Optional, Dict

from .component_base import ComponentBase
from .hardware_abstraction_level import HardwareAbstractionLevel

import claripy

class HardwarePackage(ComponentBase):
    ComponentBase.__state_slots__ = ComponentBase.__state_slots__ + ("pin_state", )
    ComponentBase.__slots__ = ComponentBase.__slots__ + ("chip_name", "chip_vendor", "pin_state",)

    def __init__(
        self,
        abstraction=HardwareAbstractionLevel.PACKAGE,
        chip_name: Optional[str] = None,
        chip_vendor: Optional[str] = None,
        pin_state: Dict[str, claripy.ast.bv.BV] = None,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.chip_name = chip_name
        self.chip_vendor = chip_vendor

        self.pin_state = pin_state or {}