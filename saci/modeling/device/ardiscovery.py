from saci.modeling.device.component.component_base import Ports

from ..communication.auth_comm import AuthenticatedCommunication
from .component.cyber import CyberComponentBinary, CyberComponentSourceCode
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from .telemetry import Telemetry, TelemetryAlgorithmic, TelemetryHigh


class ARDiscovery(Telemetry):
    """
    Describes the ARDiscovery component.
    """

    def __init__(self, ports: Ports | None = None, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: TelemetryHigh(
                name="ARDiscovery High",
                parameters=dict(
                    protocol_name="ardiscovery",
                    communication=AuthenticatedCommunication(identifier="system_id"),
                ),
            ),
            CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
