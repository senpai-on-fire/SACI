from .component import ComponentHigh, ComponentAlgorithmic
from ..communication import BaseCommunication


class TelemetryHigh(ComponentHigh):
    def __init__(self, protocol_name=None, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.protocol_name = protocol_name


class TelemetryAlgorithmic(ComponentAlgorithmic):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def accepts_communication(self, communication: BaseCommunication) -> bool:
        return True
