from ..communication.auth_comm import AuthenticatedCommunication
from .component.cyber import CyberComponentBinary, CyberComponentSourceCode
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from .telemetry import Telemetry, TelemetryAlgorithmic, TelemetryHigh


class Http(Telemetry):
    """
    Describes the HTTP component.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # TODO: ports?

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: TelemetryHigh(
                name="HTTP High",
                parameters=dict(
                    protocol_name="http",
                    communication=AuthenticatedCommunication(identifier="system_id"),
                ),
            ),
            CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
