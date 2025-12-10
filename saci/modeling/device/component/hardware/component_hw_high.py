from saci.modeling.device.component.hardware.hardware_abstraction_level import HardwareAbstractionLevel
from saci.modeling.device.component.hardware.hardware_component_base import HardwareComponentBase


class HardwareHigh(HardwareComponentBase):
    __state_slots__ = HardwareComponentBase.__state_slots__
    __slots__ = HardwareComponentBase.__slots__ + ("modality",)

    def __init__(self, abstraction=HardwareAbstractionLevel.HIGH, modality=None, **kwargs):
        super().__init__(abstraction=abstraction, **kwargs)
        self.modality = modality
