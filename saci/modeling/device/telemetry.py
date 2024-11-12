from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication



class Telemetry(CyberComponentBase):
    """
    This is the base class for all telemetry components.
    """

    __slots__ = ("has_external_input", "ABSTRACTIONS")

    def __init__(self, has_external_input=False, **kwargs):
        super().__init__(**kwargs)

        self.has_external_input = has_external_input

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: TelemetryHigh(),
            CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

class TelemetryHigh(CyberComponentHigh):
    __slots__ = ("protocol_name", "communication", )

    def __init__(self, protocol_name=None, communication=None, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.protocol_name = protocol_name
        self.communication = communication


class TelemetryAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        return True

