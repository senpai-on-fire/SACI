from typing import Optional
from saci.modeling.device.component import CyberComponentBase, CyberAbstractionLevel, CyberComponentHigh, CyberComponentAlgorithmic
from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports

class ESCHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class ESCAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class ESC(CyberComponentBase):
    def __init__(self, ports: Optional[Ports]=None, **kwargs):
        super().__init__(
            ports=union_ports({
                "Speed Value": Port(direction=PortDirection.IN),
                "Motor Control": Port(direction=PortDirection.OUT),
            }, ports),
            **kwargs
        )
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ESCHigh(),
            CyberAbstractionLevel.ALGORITHMIC: ESCAlgorithmic(),
        }
