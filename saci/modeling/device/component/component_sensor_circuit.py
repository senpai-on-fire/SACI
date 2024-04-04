from typing import Optional, Dict

from .hardware_component_base import HardwareComponentBase
from .hardware_abstraction_level import HardwareAbstractionLevel

import claripy

class SensorCircuit(HardwareComponentBase):
    __state_slots__ = HardwareComponentBase.__state_slots__ + ("internal_voltages", )
    __slots__ = HardwareComponentBase.__slots__ + ("PhysicalSensorDesign", "SignalProcessingChain", "ADC", "internal_voltages",)

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
    