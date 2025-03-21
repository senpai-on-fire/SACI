from saci.modeling.device.component import (
    HardwareComponentBase,
    HardwareAbstractionLevel,
    HardwareHigh,
    HardwareCircuit,
)
from saci.modeling.device.component.component_base import Port, PortDirection, union_ports


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
        super().__init__(
            ports=union_ports(
                {
                    "Connector": Port(direction=PortDirection.INOUT),
                },
                ports,
            ),
            **kwargs,
        )
        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: BatteryHigh(),
            HardwareAbstractionLevel.CIRCUIT: BatteryCircuit(),
        }
