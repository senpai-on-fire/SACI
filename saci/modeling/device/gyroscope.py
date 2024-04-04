import logging

from .component import CyberComponentHigh, CyberComponentAlgorithmic
#from .component import HardwareHigh, HardwarePackage, HardwareTechnology
_l = logging.getLogger(__name__)

import claripy


# High/Algorithmic/Source are placeholder abstraction levels
class GyroscopeHigh(CyberComponentHigh):
    def __init__(self, **kwargs):
        super().__init__(has_external_input=True, **kwargs)


class GyroscopeAlgorithmic(CyberComponentAlgorithmic):
    def __init__(self, precision_bits = 14, **kwargs):
        super().__init__(**kwargs)
        # For 6-DoF IMU:
        # self.v["dx_reading"] = claripy.BVS("dx_reading", precision_bits)
        # self.v["dy_reading"] = claripy.BVS("dy_reading", precision_bits)
        # self.v["dz_reading"] = claripy.BVS("dz_reading", precision_bits)
        # self.v["drx_reading"] = claripy.BVS("drx_reading", precision_bits)
        # self.v["dry_reading"] = claripy.BVS("dry_reading", precision_bits)
        # self.v["drz_reading"] = claripy.BVS("drz_reading", precision_bits)
        self.v["readings"] = claripy.BVS("readings", precision_bits * 6) # More general and probably more efficient


#class GyroscopeHWHigh(HardwareHigh):
#    def __init__(self, **kwargs):
#        super().__init__(modality="gyroscope", **kwargs)
#
#class GyroscopeHWPackage(HardwarePackage):
#    KNOWN_CHIP_NAMES = [
#        'L3G4200D', 'L3GD20', 'LSM330', 'LPR5150AL', 'LPY503AL', 'MPU3050', 'MPU6000', 'MPU6050', 'MPU6500', 'MPU9150',
#        'MPU9250', 'IMU3000', 'ITG3200', 'IXZ650', 'ADXRS610', 'ENC-03MB'
#    ]
#    def __init__(self, gyro_name, gyro_vendor, **kwargs):
#        super().__init__(chip_name = gyro_name, chip_vendor = gyro_vendor, **kwargs)
#        if gyro_name not in self.KNOWN_CHIP_NAMES:
#            _l.warning(f"Unknown gyroscope chip name: {gyro_name}. Please add it to the list in GyroscopeHWPackage")
#
#class GyroscopeHWTechnology(HardwareTechnology):
#    KNOWN_TECHNOLOGIES = [
#        'MEMS', 'Fiber Optic', 'Inertial'
#    ]
#    def __init__(self, technology, **kwargs):
#        super().__init__(technology = technology, **kwargs)
#        if technology not in self.KNOWN_TECHNOLOGIES:
#            _l.warning(f"Unknown gyroscope technology: {technology}. Please add it to the list in GyroscopeHWTechnology")
