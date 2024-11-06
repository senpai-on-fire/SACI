from .component import CyberComponentHigh, CyberComponentAlgorithmic


class CompassSensorHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(has_external_input=True, **kwargs)

class CompassSensorAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
