from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase
from ..communication import BaseCommunication

from typing import List


class LocalizerHigh(CyberComponentHigh):
    __slots__ = ("enable", )

    def __init__(self, enable=False, **kwargs):
        super().__init__(**kwargs)
        self.enable = enable


class LocalizerAlgorithm(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def position(self, localization_components: List[CyberComponentBase]) -> bool:
        raise NotImplementedError