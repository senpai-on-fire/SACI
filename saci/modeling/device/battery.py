from saci.modeling.device.component import (
    HardwareComponentBase,
    HardwareAbstractionLevel,
    HardwareHigh,
    HardwareCircuit,
)
from saci.modeling.device.component.component_base import Port, PortDirection


class BatteryHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class BatteryCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class Battery(HardwareComponentBase):
    def __init__(self, ports=None, **kwargs):
        if ports is None:
            ports = ports or {
                "Connector": Port(direction=PortDirection.INOUT),
            }
        super().__init__(ports=ports, **kwargs)
        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: BatteryHigh(),
            HardwareAbstractionLevel.CIRCUIT: BatteryCircuit(),
        }
