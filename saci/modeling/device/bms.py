from typing import Optional
from saci.modeling.device.component import (
    CyberComponentBase,
    CyberAbstractionLevel,
    CyberComponentHigh,
    CyberComponentAlgorithmic,
)
from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports


class BMSHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class BMSAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class BMS(CyberComponentBase):
    def __init__(self, ports: Optional[Ports] = None, **kwargs):
        super().__init__(
            ports=union_ports(
                {
                    "Battery": Port(direction=PortDirection.INOUT),
                    "Power": Port(direction=PortDirection.OUT),
                    "Monitoring": Port(direction=PortDirection.OUT),
                },
                ports,
            ),
            **kwargs,
        )
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: BMSHigh(),
            CyberAbstractionLevel.ALGORITHMIC: BMSAlgorithmic(),
        }
