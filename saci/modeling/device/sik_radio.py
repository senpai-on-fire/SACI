
from ..communication.auth_comm import AuthenticatedCommunication
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from .component.cyber import CyberComponentSourceCode, CyberComponentBinary
from .telemetry import Telemetry, TelemetryHigh, TelemetryAlgorithmic


class SikRadio(Telemetry):
    """
    Describes Sik radio.
    """
    def __init__(self, has_external_input=True, **kwargs):
        super().__init__(has_external_input=has_external_input, **kwargs)
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
