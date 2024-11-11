from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication


class WifiHigh(CyberComponentHigh):
    __slots__ = ("protocol_name", "communication", "protection")

    def __init__(self, protocol_name=None, communication=None, protection=None, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.protocol_name = protocol_name
        self.communication = communication
        self.protection = protection


class WifiAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        return True


class Wifi(CyberComponentBase):
    """
    This is the base class for all telemetry components.
    """

    __slots__ = ("ABSTRACTIONS", "has_external_input")

    def __init__(self, has_external_input=True, protection=None, **kwargs):
        super().__init__(**kwargs)
        
        self.has_external_input = has_external_input

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: WifiHigh(protection=protection),
            CyberAbstractionLevel.ALGORITHMIC: WifiAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
