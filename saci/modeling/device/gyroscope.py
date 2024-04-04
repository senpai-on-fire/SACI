import logging

from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentSourceCode

_l = logging.getLogger(__name__)


# High/Algorithmic/Source are placeholder abstraction levels
class GyroscopeHigh(CyberComponentHigh):
    SUPPORTED_CHIP_TYPES = ["MEMS", "Inertial"]
    __slots__ = CyberComponentHigh.__slots__ + ('chip_type',)

    def __init__(self, chip_type=None, **kwargs):
        super().__init__(has_external_input=False, **kwargs)
        self.chip_type = chip_type if chip_type in self.SUPPORTED_CHIP_TYPES else None
        if self.chip_type is None:
            _l.warning(f"Unsupported chip type: {chip_type}")


class GyroscopeAlgorithmic(CyberComponentAlgorithmic):
    KNOWN_CHIP_NAMES = [
        'L3G4200D', 'L3GD20', 'LSM330', 'LPR5150AL', 'LPY503AL', 'MPU3050', 'MPU6000', 'MPU6050', 'MPU6500', 'MPU9150',
        'MPU9250', 'IMU3000', 'ITG3200', 'IXZ650', 'ADXRS610', 'ENC-03MB'
    ]
    __slots__ = CyberComponentAlgorithmic.__slots__ + ('chip_name',)

    def __init__(self, chip_name, **kwargs):
        super().__init__(**kwargs)
        self.chip_name = chip_name if chip_name in self.KNOWN_CHIP_NAMES else None
        if self.chip_name is None:
            _l.warning(f"Modeling an unknown chip name: {chip_name}")


class GyroscopeSource(CyberComponentSourceCode):
    __slots__ = CyberComponentSourceCode.__slots__ + ('harmonic_frequency',)

    def __init__(self, harmonic_frequency, **kwargs):
        super().__init__(**kwargs)
        self.harmonic_frequency = harmonic_frequency
