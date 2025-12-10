from ..communication.auth_comm import AuthenticatedCommunication
from .component.cyber import CyberComponentBinary, CyberComponentSourceCode
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from .telemetry import Telemetry, TelemetryAlgorithmic, TelemetryHigh


class Mavlink(Telemetry):
    """
    Describes the Mavlink component.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: TelemetryHigh(
                name="Mavlink High",
                parameters=dict(
                    protocol_name="mavlink",
                    communication=AuthenticatedCommunication(identifier="system_id"),
                ),
            ),
            CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
