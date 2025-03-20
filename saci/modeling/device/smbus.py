from .component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication


class SMBusHigh(CyberComponentHigh):
    __slots__ = ("communication", "protection")

    def __init__(self, communication=None, protection=None, **kwargs):
        super().__init__(**kwargs)
        self.communication = communication
        self.protection = protection

    parameter_types = {"supported_protocols": list}


class SMBusAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        # TODO: depends on the protocol
        if any(isinstance(communication, protocol) for protocol in self.parameters["supported_protocols"]):
            return True
        # TODO: depends on the protocol
        else:
            return False

    parameter_types = {"supported_protocols": list}


class SMBus(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.ABSTRACTIONS = {
            # TODO: ports?
            CyberAbstractionLevel.HIGH: SMBusHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: SMBusAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {"supported_protocols": list}
