from saci.modeling.device.component.hardware.hardware_component_base import HardwareComponentBase
from saci.modeling.device.component.hardware.hardware_abstraction_level import HardwareAbstractionLevel

import claripy


class HardwareCircuit(HardwareComponentBase):
    __state_slots__ = HardwareComponentBase.__state_slots__ + ("internal_voltages",)
    __slots__ = HardwareComponentBase.__slots__ + (
        "PhysicalCircuitDesign",
        "SignalProcessingChain",
        "ADC",
        "internal_voltages",
    )

    def __init__(
        self,
        abstraction=HardwareAbstractionLevel.CIRCUIT,
        PhysicalCircuitDesign=None,
        SignalProcessingChain=None,
        ADC=None,
        internal_voltages: dict[str, claripy.ast.bv.BV] | None = None,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.PhysicalCircuitDesign = PhysicalCircuitDesign
        self.SignalProcessingChain = SignalProcessingChain
        self.ADC = ADC
        self.internal_voltages = internal_voltages or {}

    @property
    def v(self):
        return self.internal_voltages
