from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication


class TelemetryHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("protocol_name",)

    def __init__(self, protocol_name=None, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.protocol_name = protocol_name


class TelemetryAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        return True


class Telemetry(CyberComponentBase):
    """
    This is the base class for all telemetry components.
    """

    ABSTRACTIONS = {
        CyberAbstractionLevel.HIGH: TelemetryHigh,
        CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic,
        CyberAbstractionLevel.SOURCE: CyberComponentSourceCode,
        CyberAbstractionLevel.BINARY: CyberComponentBinary,
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
