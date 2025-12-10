from ..communication.auth_comm import AuthenticatedCommunication
from .component.cyber import CyberComponentBinary, CyberComponentSourceCode
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from .telemetry import Telemetry, TelemetryAlgorithmic, TelemetryHigh


class SikRadio(Telemetry):
    """
    Describes Sik radio.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: TelemetryHigh(
                name="Sik Radio High",
                parameters=dict(
                    protocol_name="sik",
                    communication=AuthenticatedCommunication(identifier="netid"),
                ),
            ),
            CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
