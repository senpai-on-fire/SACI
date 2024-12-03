from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication, UARTProtocol


class SerialHigh(CyberComponentHigh):
    __slots__ = ("protocol_name", "communication", "protection")

    def __init__(self, supported_protocols=None, communication=None, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.supported_protocols = supported_protocols
        self.communication = communication


class SerialAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, supported_protocols=None, **kwargs):
        super().__init__(**kwargs)
        self.supported_protocols = supported_protocols

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        # TODO: depends on the protocol
        if any(isinstance(communication, protocol) for protocol in self.supported_protocols):
            return True
        # TODO: depends on the protocol
        else:
            return False


class Serial(CyberComponentBase):

    __slots__ = ("ABSTRACTIONS", "has_external_input", "supported_protocols")

    def __init__(self, has_external_input=True, supported_protocols=None, **kwargs):
        super().__init__(**kwargs)
        
        self.has_external_input = has_external_input

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: SerialHigh(supported_protocols=supported_protocols),
            CyberAbstractionLevel.ALGORITHMIC: SerialAlgorithmic(supported_protocols=supported_protocols),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
