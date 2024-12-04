from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication


class WifiHigh(CyberComponentHigh):
    __slots__ = ("supported_protocols", "protection", "communication", "encryption_type")

    def __init__(self, supported_protocols=None, communication=None, protection=None, encryption_type=None, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.communication = communication
        self.encryption_type = encryption_type
        self.supported_protocols = supported_protocols
        self.protection = protection

class WifiAlgorithmic(CyberComponentAlgorithmic):

    __slots__ = CyberComponentAlgorithmic.__slots__ + ("supported_protocols",)

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

class Wifi(CyberComponentBase):
    """
    This is the base class for all telemetry components.
    """

    __slots__ = ("ABSTRACTIONS", "has_external_input")

    def __init__(self, has_external_input=True, supported_protocols=None, protection=None, encryption_type=None, **kwargs):
        super().__init__(**kwargs)
        
        self.has_external_input = has_external_input

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: WifiHigh(supported_protocols=supported_protocols, protection=protection, encryption_type=encryption_type),
            CyberAbstractionLevel.ALGORITHMIC: WifiAlgorithmic(supported_protocols=supported_protocols),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
