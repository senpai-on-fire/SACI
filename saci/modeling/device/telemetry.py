from .component import ComponentHigh, ComponentAlgorithmic
from ..communication import BaseCommunication


class TelemetryHigh(ComponentHigh):
    __slots__ = ComponentHigh.__slots__ + ("protocol_name",)

    def __init__(self, protocol_name=None, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.protocol_name = protocol_name


class TelemetryAlgorithmic(ComponentAlgorithmic):
    __slots__ = ComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        return True
