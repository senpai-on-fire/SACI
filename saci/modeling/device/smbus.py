from .component import CyberComponentHigh, CyberComponentAlgorithmic
from ..communication import BaseCommunication


class SMBus(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)