from typing import Optional
from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports
from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel

class DNNHigh(CyberComponentHigh):
    @property
    def parameter_types(self):
        return {
            "known_source": bool,
            "known_weight": bool,
        }


class DNNAlgorithmic(CyberComponentAlgorithmic):
    @property
    def parameter_types(self):
        return {
            "known_source": bool,
            "known_weight": bool,
        }

class DNN(CyberComponentBase):
    def __init__(self, ports: Optional[Ports]=None, **kwargs):
        super().__init__(
            ports=union_ports({
                # TODO: lol
                "Input": Port(direction=PortDirection.IN),
                "Output": Port(direction=PortDirection.OUT),
            }, ports),
            **kwargs
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: DNNHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: DNNAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    @property
    def parameter_types(self):
        return {
            "known_source": bool,
            "known_weight": bool,
        }
