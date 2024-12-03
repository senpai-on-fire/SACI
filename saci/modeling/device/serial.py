from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication


class SerialHigh(CyberComponentHigh):
    __slots__ = ("protocol_name", "communication", "protection")

    def __init__(self, protocol_name=None, communication=None, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.protocol_name = protocol_name
        self.communication = communication


class SerialAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        return True


class Serial(CyberComponentBase):

    __slots__ = ("ABSTRACTIONS", "has_external_input")

    def __init__(self, has_external_input=True, protocol_name=None, **kwargs):
        super().__init__(**kwargs)
        
        self.has_external_input = has_external_input

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: SerialHigh(protocol_name=protocol_name),
            CyberAbstractionLevel.ALGORITHMIC: SerialAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
