from typing import Optional
from saci.modeling.device.component.component_base import Port, PortDirection, Ports
from .component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class DNNHigh(CyberComponentHigh):
    parameter_types = {
        "known_source": bool,
        "known_weight": bool,
    }


class DNNAlgorithmic(CyberComponentAlgorithmic):
    parameter_types = {
        "known_source": bool,
        "known_weight": bool,
    }


class DNN(CyberComponentBase):
    def __init__(self, ports: Optional[Ports] = None, **kwargs):
        if ports is None:
            ports = {
                "Input": Port(direction=PortDirection.IN),
                "Output": Port(direction=PortDirection.OUT),
            }
        super().__init__(ports=ports, **kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: DNNHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: DNNAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "known_source": bool,
        "known_weight": bool,
    }
