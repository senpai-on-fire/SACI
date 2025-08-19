from typing import Optional

from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports
from .component import CyberComponentHigh, CyberComponentBase, CyberAbstractionLevel


class WebServerHigh(CyberComponentHigh):
    parameter_types = {
        "protocol_name": str,
        "has_authentication": bool,
    }


class WebServer(CyberComponentBase):
    def __init__(self, ports: Optional[Ports] = None, **kwargs):
        super().__init__(
            ports=union_ports(
                {
                    "Socket": Port(direction=PortDirection.INOUT),
                    # and then in the additional ports that get unioned in are device-specific control inputs/outputs
                },
                ports,
            ),
            **kwargs,
        )
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: WebServerHigh(**kwargs),
        }

    parameter_types = {
        "protocol_name": str,
        "has_authentication": bool,
    }
