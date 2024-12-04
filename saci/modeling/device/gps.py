from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication, GPSProtocol

class GPSReceiverHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("supported_protocols", "authenticated", "signal_strength_threshold")

    def __init__(self, supported_protocols=None, authenticated=False, signal_strength_threshold=-100, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.supported_protocols = supported_protocols
        self.authenticated = authenticated
        self.signal_strength_threshold = signal_strength_threshold


class GPSReceiverAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + ("supported_protocols",)

    def __init__(self, supported_protocols=None, **kwargs):
        super().__init__(**kwargs)
        self.supported_protocols = supported_protocols

    def is_signal_valid(self, signal_strength):
        # Determines if the received GPS signal meets the strength threshold.
        return signal_strength >= self.signal_strength_threshold

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        if self.is_signal_valid(communication.signal_strength):
            if any(isinstance(communication, protocol) for protocol in self.supported_protocols):
                return True
        return False


class GPSReceiver(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "has_external_input")

    def __init__(self, has_external_input=True, supported_protocols=None, **kwargs):
        super().__init__(**kwargs)
        
        self.has_external_input = has_external_input

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: GPSReceiverHigh(supported_protocols=supported_protocols),
            CyberAbstractionLevel.ALGORITHMIC: GPSReceiverAlgorithmic(supported_protocols=supported_protocols),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }