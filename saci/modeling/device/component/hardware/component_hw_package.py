from typing import Optional, Dict

from saci.modeling.device.component.hardware.hardware_component_base import HardwareComponentBase
from saci.modeling.device.component.hardware.hardware_abstraction_level import HardwareAbstractionLevel

import claripy

class HardwarePackage(HardwareComponentBase):
    __state_slots__ = HardwareComponentBase.__state_slots__ + ("pin_state", )
    __slots__ = HardwareComponentBase.__slots__ + ("chip_name", "chip_vendor", "pin_state",)

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