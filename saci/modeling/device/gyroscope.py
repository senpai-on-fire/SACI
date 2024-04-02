from .component import ComponentHigh, ComponentAlgorithmic, ComponentSourceCode
from ..communication import BaseCommunication


# High/Algorithmic/Source are placeholder abstraction levels
class GyroscopeHigh(ComponentHigh):
    def __init__(self, chip_type=None, **kwargs):
        super().__init__(has_external_input=False, **kwargs)
        if chip_type not in ["MEMS", "Inertial"]:
            chip_type = None # Unsupported chip type
        self.chip_type = chip_type


class GyroscopeAlgorithmic(ComponentAlgorithmic):
    def __init__(self, chip_name, **kwargs):
        super().__init__(**kwargs)
        # Known chip names, some of which are vulnerable to rocking drones
        known_chip_names = ['L3G4200D', 'L3GD20', 'LSM330', 'LPR5150AL', 'LPY503AL', 'MPU3050', 'MPU6000', 'MPU6050', 'MPU6500', 'MPU9150', 'MPU9250', 'IMU3000', 'ITG3200', 'IXZ650', 'ADXRS610', 'ENC-03MB']
        if chip_name not in known_chip_names:
            chip_name = None
        self.chip_name = chip_name


class GyroscopeSource(ComponentSourceCode):
    def __init__(self, harmonic_frequency, **kwargs):
        super().__init__(**kwargs)
        self.harmonic_frequency = harmonic_frequency
