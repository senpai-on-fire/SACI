from .component import CyberComponentHigh, CyberComponentAlgorithmic
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
