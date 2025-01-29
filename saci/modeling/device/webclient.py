from .component import CyberComponentHigh, CyberComponentBase, CyberAbstractionLevel


class WebClientHigh(CyberComponentHigh):
    __state_slots__ = CyberComponentHigh.__state_slots__ + ("protocol_name", "has_authentication")
    __slots__ = CyberComponentHigh.__slots__ + ("protocol_name", "has_authentication")

    def __init__(self, protocol_name=None, has_authentication=None, **kwargs):
        """
        :param protocol_name:
        :param has_authentication:
        :param kwargs:
        """
        super().__init__(**kwargs)
        self.protocol_name = protocol_name
        self.has_authentication = has_authentication


class WebClient(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: WebClientHigh(),
        }
