from claripy import BVS
import logging

from .sensor import SensorHigh, SensorAlgorithmic, Sensor
from saci.modeling.device.component import HardwarePackage, HardwareTechnology, HardwareHigh
from saci.modeling.device.component import CyberAbstractionLevel, CyberComponentSourceCode, CyberComponentBinary

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================

class CompassSensorHigh(SensorHigh):

    __slots__ = SensorHigh.__slots__ + ("has_external_input", "is_calibrated", "error_flag")

    def __init__(self, has_external_input=True, is_calibrated=False, error_flag=False, **kwargs):
        """
        :param has_external_input: Indicates if the compass is influenced by external factors.
        :param is_calibrated: Whether the compass has been calibrated.
        :param error_flag: Flag indicating whether an anomaly has been detected.
        """
        super().__init__(**kwargs)
        self.has_external_input = has_external_input
        self.is_calibrated = is_calibrated
        self.error_flag = error_flag  # Tracks if the sensor output is compromised

        # High-level state variables
        self.variables["is_calibrated"] = BVS("compass_is_calibrated", 1)
        self.variables["heading_simple"] = BVS("compass_heading_simple", 16)  # Coarse heading


# =================== Algorithmic Abstraction ===================

class CompassSensorAlgorithmic(SensorAlgorithmic):

    __slots__ = SensorAlgorithmic.__slots__ + ("error_flag",)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Example symbolic variables for precise compass modeling
        self.variables["heading"] = BVS("compass_heading", 32)  # Heading in degrees
        self.variables["declination"] = BVS("compass_declination", 32)  # Angle offset from true north
        self.variables["noise_level"] = BVS("compass_noise", 32)  # Noise interference level

        self.error_flag = BVS("compass_error_flag", 1)  # Tracks anomalies

    def get_heading(self):
        """
        Retrieves the compass heading.
        """
        return self.variables["heading"]


# =================== Full Sensor Abstraction ===================

class CompassSensor(Sensor):

    __slots__ = ("has_external_input", "ABSTRACTIONS")

    def __init__(self, has_external_input=True, **kwargs):
        super().__init__(**kwargs)

        self.has_external_input = has_external_input

        high_abstraction = CompassSensorHigh(has_external_input=has_external_input)
        algo_abstraction = CompassSensorAlgorithmic()

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== Hardware Abstractions ===================

class CompassHardware(Sensor):

    __slots__ = Sensor.__slots__

    def __init__(self, has_external_input=True, i2c_address=0x1E, spi_channel=0, **kwargs):
        """
        :param has_external_input: Whether the sensor is influenced by external magnetic fields.
        :param i2c_address: I2C address for communication.
        :param spi_channel: SPI channel if using an SPI-based sensor.
        """
        super().__init__(**kwargs)
        self.has_external_input = has_external_input
        self.i2c_address = i2c_address
        self.spi_channel = spi_channel

        # Simulated hardware register values
        self.variables["hardware_status"] = BVS("compass_hw_status", 8)  # 8-bit status register
        self.variables["hardware_config"] = BVS("compass_hw_config", 16)  # 16-bit config register


class CompassHWPackage(HardwarePackage):

    KNOWN_CHIP_NAMES = [
        "HMC5883L", "QMC5883L", "LSM303", "MPU9250", "AK8963", "MAG3110", "MMC5983MA"
    ]

    def __init__(self, compass_name, compass_vendor, **kwargs):
        """
        :param compass_name: The name of the compass (magnetometer) chip.
        :param compass_vendor: The manufacturer of the compass chip.
        """
        super().__init__(chip_name=compass_name, chip_vendor=compass_vendor, **kwargs)
        if compass_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(f"Unknown compass chip name: {compass_name}. Please add it to CompassHWPackage.")


class CompassHWTechnology(HardwareTechnology):

    KNOWN_TECHNOLOGIES = ["MEMS", "Fluxgate", "Magnetoresistive", "Hall Effect"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of compass technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown compass technology: {technology}. Please add it to CompassHWTechnology.")

######################################################    OLD VERSION    ########################################################################


# from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
# from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel


# class CompassSensorHigh(CyberComponentHigh):
#     __slots__ = CyberComponentHigh.__slots__

#     def __init__(self, **kwargs):
#         super().__init__(has_external_input=True, **kwargs)

# class CompassSensorAlgorithmic(CyberComponentAlgorithmic):
#     __slots__ = CyberComponentAlgorithmic.__slots__

#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)


# class CompassSensor(CyberComponentBase):
#     __slots__ = ("has_external_input", "ABSTRACTIONS")

#     def __init__(self, has_external_input=True, **kwargs):
#         super().__init__(**kwargs)

#         self.has_external_input = has_external_input

#         self.ABSTRACTIONS = {
#             CyberAbstractionLevel.HIGH: CompassSensorHigh(),
#             CyberAbstractionLevel.ALGORITHMIC: CompassSensorAlgorithmic(),
#             CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
#             CyberAbstractionLevel.BINARY: CyberComponentBinary(),
#         }
