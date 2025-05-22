import claripy
import logging

# Adjust these imports based on your project structure
from .sensor import SensorHigh, SensorAlgorithmic, Sensor
from saci.modeling.device.component import HardwarePackage, HardwareTechnology
from saci.modeling.device.component import CyberAbstractionLevel, CyberComponentSourceCode, CyberComponentBinary

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================


class OpticalFlowSensorHigh(SensorHigh):
    __slots__ = SensorHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Optionally store high-level flags, aggregated data, etc.
        self.variables["is_calibrated"] = claripy.BVS("of_calibrated", 1)
        self.variables["motion_detected"] = claripy.BVS("of_motion_detected", 1)


# =================== Algorithmic Abstraction ===================


class OpticalFlowSensorAlgorithmic(SensorAlgorithmic):
    __slots__ = SensorAlgorithmic.__slots__ + ("uses_corner_detection", "enabled")

    def __init__(self, uses_corner_detection=True, enabled=True, **kwargs):
        """
        :param uses_corner_detection: Whether the sensor processes optical flow using corner detection.
        :param enabled: Whether the sensor is enabled.
        """
        super().__init__(**kwargs)

        self.uses_corner_detection = uses_corner_detection
        self.enabled = enabled

        # Symbolic variables to represent optical flow data
        self.variables["flow_data"] = claripy.BVS("of_flow_data", 128)

        # Optionally, store X/Y displacement for multiple points
        self.variables["displacements"] = claripy.BVS("of_displacements", 32 * 10)

        self.variables["noise"] = claripy.BVS("of_noise", 32)
        self.variables["motion_vector"] = claripy.BVS("of_motion_vector", 64)


# =================== Full Sensor Abstraction ===================


class OpticalFlowSensor(Sensor):
    __slots__ = ("uses_corner_detection", "enabled", "ABSTRACTIONS")

    def __init__(self, uses_corner_detection=True, enabled=True, **kwargs):
        super().__init__(**kwargs)

        high_abstraction = OpticalFlowSensorHigh()
        algo_abstraction = OpticalFlowSensorAlgorithmic(uses_corner_detection=uses_corner_detection, enabled=enabled)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== Hardware Abstractions ===================


class OpticalFlowSensorHardware(Sensor):
    __slots__ = Sensor.__slots__

    def __init__(self, i2c_address=0x42, spi_channel=0, **kwargs):
        """
        :param i2c_address: I2C address for communication.
        :param spi_channel: SPI channel if using an SPI-based sensor.
        """
        super().__init__(**kwargs)
        self.i2c_address = i2c_address
        self.spi_channel = spi_channel
        self.variables = {}  # Initialize variables dictionary

        # Simulated hardware register values
        self.variables["hardware_status"] = claripy.BVS("of_hw_status", 8)  # 8-bit status register
        self.variables["hardware_config"] = claripy.BVS("of_hw_config", 16)  # 16-bit config register


class OpticalFlowSensorHWPackage(HardwarePackage):
    KNOWN_CHIP_NAMES = ["PMW3901", "PX4FLOW", "VL53L1X", "CX-OF"]

    def __init__(self, sensor_name, sensor_vendor, **kwargs):
        """
        :param sensor_name: The name of the optical flow sensor chip.
        :param sensor_vendor: The manufacturer of the optical flow sensor chip.
        """
        super().__init__(chip_name=sensor_name, chip_vendor=sensor_vendor, **kwargs)
        if sensor_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(
                f"Unknown optical flow sensor chip name: {sensor_name}. Please add it to OpticalFlowSensorHWPackage."
            )


class OpticalFlowSensorHWTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["Optical Flow", "Lidar-Assisted", "Time-of-Flight", "Infrared"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of optical flow sensor technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(
                f"Unknown optical flow sensor technology: {technology}. Please add it to OpticalFlowSensorHWTechnology."
            )
