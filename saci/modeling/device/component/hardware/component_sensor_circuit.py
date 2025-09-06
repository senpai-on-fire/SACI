import claripy

from saci.modeling.device.component.hardware.hardware_abstraction_level import HardwareAbstractionLevel
from saci.modeling.device.component.hardware.hardware_component_base import HardwareComponentBase


class SensorCircuit(HardwareComponentBase):
    __state_slots__ = HardwareComponentBase.__state_slots__ + ("internal_voltages",)
    __slots__ = HardwareComponentBase.__slots__ + (
        "PhysicalSensorDesign",
        "SignalProcessingChain",
        "ADC",
        "internal_voltages",
    )

    def __init__(
        self,
        abstraction=HardwareAbstractionLevel.CIRCUIT,
        PhysicalSensorDesign=None,
        SignalProcessingChain=None,
        ADC=None,
        internal_voltages: dict[str, claripy.ast.bv.BV] | None = None,
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
