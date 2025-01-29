
from ..communication.auth_comm import AuthenticatedCommunication
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from .component.cyber import CyberComponentSourceCode, CyberComponentBinary
from .telemetry import Telemetry, TelemetryHigh, TelemetryAlgorithmic


class FTP(Telemetry):
    """
    Describes the FTP component.
    """

    def __init__(self, has_external_input=False, **kwargs):
        super().__init__(has_external_input=has_external_input, **kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: TelemetryHigh(
                name="FTP High",
                protocol_name="ftp",
                communication=AuthenticatedCommunication(identifier="system_id"),
            ),
            CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
