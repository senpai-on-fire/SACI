from .component import ComponentHigh, ComponentAlgorithmic, ComponentBase
from ..communication import BaseCommunication

from typing import List


class LocalizerHigh(ComponentHigh):
    def __init__(self, enable=False, **kwargs):
        super().__init__(**kwargs)
        self.enable = enable


class LocalizerAlgorithm(ComponentAlgorithmic):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def position(self, localization_components: List[ComponentBase]) -> bool:
        raise NotImplementedError