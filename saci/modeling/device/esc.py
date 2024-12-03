from ..component import CyberComponentBase, CyberAbstractionLevel, CyberComponentHigh, CyberComponentAlgorithmic

class ESCHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class ESCAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class ESC(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ESCHigh(),
            CyberAbstractionLevel.ALGORITHMIC: ESCAlgorithmic(),
        }
