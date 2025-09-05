from typing import Optional

from saci.modeling.device.component.component_base import Port, PortDirection, Ports
from .component import CyberComponentHigh, CyberComponentBase, CyberAbstractionLevel


class WebServerHigh(CyberComponentHigh):
    parameter_types = {
        "protocol_name": str,
        "has_authentication": bool,
    }


class WebServer(CyberComponentBase):
    def __init__(self, ports: Optional[Ports] = None, **kwargs):
        if ports is None:
            ports = {
                "Socket": Port(direction=PortDirection.INOUT),
            }
        super().__init__(ports=ports, **kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: WebServerHigh(**kwargs),
        }

    parameter_types = {
        "protocol_name": str,
        "has_authentication": bool,
    }
