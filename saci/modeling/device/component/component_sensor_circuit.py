from typing import Optional, Dict

from .component_base import ComponentBase
from .hardware_abstraction_level import HardwareAbstractionLevel

import claripy

class SensorCircuit(ComponentBase):
    ComponentBase.__state_slots__ = ComponentBase.__state_slots__ + ("internal_voltages", )
    ComponentBase.__slots__ = ComponentBase.__slots__ + ("PhysicalSensorDesign", "SignalProcessingChain", "ADC", "internal_voltages",)

    def __init__(
        self,
        abstraction=HardwareAbstractionLevel.CIRCUIT,
        PhysicalSensorDesign = None,
        SignalProcessingChain = None,
        ADC = None, 
        internal_voltages: Dict[str, claripy.ast.bv.BV] = None,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.PhysicalSensorDesign = PhysicalSensorDesign
        self.SignalProcessingChain = SignalProcessingChain
        self.ADC = ADC
        self.internal_voltages = internal_voltages or {}
    
    @property
    def v(self):
        return self.internal_voltages
    