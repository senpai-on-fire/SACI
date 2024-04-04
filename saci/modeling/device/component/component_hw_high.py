from .component_base import ComponentBase
from .hardware_abstraction_level import HardwareAbstractionLevel


class HardwareHigh(ComponentBase):
    ComponentBase.__state_slots__ = ComponentBase.__state_slots__
    ComponentBase.__slots__ = ComponentBase.__slots__ + ("modality",)

    def __init__(self, abstraction=HardwareAbstractionLevel.HIGH, modality = None, **kwargs):
        super().__init__(abstraction=abstraction, **kwargs)
        self.modality = modality



