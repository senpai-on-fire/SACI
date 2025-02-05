import logging
import claripy

# Adjust these imports to match your project’s structure:
from .sensor import SensorHigh, SensorAlgorithmic, Sensor
from saci.modeling.device.component import HardwarePackage, HardwareTechnology, HardwareHigh
from saci.modeling.device.component import CyberAbstractionLevel, CyberComponentSourceCode, CyberComponentBinary

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================

class MagnetometerHigh(SensorHigh):

    __slots__ = SensorHigh.__slots__ + ("is_calibrated", "error_flag")

    def __init__(self, is_calibrated=False, error_flag=False, **kwargs):
        """
        :param is_calibrated: Whether the magnetometer is calibrated.
        :param error_flag: Flag indicating whether an anomaly has been detected.
        """
        super().__init__(**kwargs)
        self.is_calibrated = is_calibrated
        self.error_flag = error_flag  # Tracks if the sensor output is compromised

        # High-level state variables
        self.variables["is_calibrated"] = claripy.BVS("mag_is_calibrated", 1)
        self.variables["external_magnetic_influence"] = claripy.BVS("mag_external_influence", 1)


# =================== Algorithmic Abstraction ===================

class MagnetometerAlgorithmic(SensorAlgorithmic):

    __slots__ = SensorAlgorithmic.__slots__ + ("precision_bits", "error_flag")

    def __init__(self, precision_bits=16, **kwargs):
        """
        :param precision_bits: Bit resolution of magnetometer readings.
        """
        super().__init__(**kwargs)
        self.precision_bits = precision_bits

        # Store X, Y, Z in a single bit-vector
        self.variables["readings"] = claripy.BVS("magneto_readings", precision_bits * 3)

        # Optionally add sensor-specific attributes
        self.variables["bias"] = claripy.BVS("magneto_bias", precision_bits)
        self.variables["noise_level"] = claripy.BVS("magneto_noise", precision_bits)
        self.variables["temperature_effect"] = claripy.BVS("magneto_temp_effect", precision_bits)

        self.error_flag = claripy.BVS("magneto_error_flag", 1)  # Tracks anomalies


# =================== Full Sensor Abstraction ===================

class Magnetometer(Sensor):

    __slots__ = ("precision_bits", "ABSTRACTIONS")

    def __init__(self, precision_bits=16, **kwargs):
        """
        :param precision_bits: Bit resolution for data representation.
        """
        super().__init__(**kwargs)


        high_abstraction = MagnetometerHigh()
        algo_abstraction = MagnetometerAlgorithmic(precision_bits=precision_bits)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== Hardware Abstractions ===================

class MagnetometerHardware(Sensor):

    __slots__ = Sensor.__slots__

    def __init__(self, i2c_address=0x1E, spi_channel=0, **kwargs):
        """
        :param i2c_address: I2C address for communication.
        :param spi_channel: SPI channel if using an SPI-based sensor.
        """
        super().__init__(**kwargs)
        self.i2c_address = i2c_address
        self.spi_channel = spi_channel
        self.variables = {}  # Initialize variables dictionary

        # Simulated hardware register values
        self.variables["hardware_status"] = claripy.BVS("magneto_hw_status", 8)  # 8-bit status register
        self.variables["hardware_config"] = claripy.BVS("magneto_hw_config", 16)  # 16-bit config register


class MagnetometerHWPackage(HardwarePackage):

    KNOWN_CHIP_NAMES = [
        "HMC5883L", "QMC5883L", "LSM303", "MPU9250", "AK8963", "MAG3110", "MMC5983MA"
    ]

    def __init__(self, magnetometer_name, magnetometer_vendor, **kwargs):
        """
        :param magnetometer_name: The name of the magnetometer chip.
        :param magnetometer_vendor: The manufacturer of the magnetometer chip.
        """
        super().__init__(chip_name=magnetometer_name, chip_vendor=magnetometer_vendor, **kwargs)
        if magnetometer_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(f"Unknown magnetometer chip name: {magnetometer_name}. Please add it to MagnetometerHWPackage.")


class MagnetometerHWTechnology(HardwareTechnology):

    KNOWN_TECHNOLOGIES = ["MEMS", "Fluxgate", "Magnetoresistive", "Hall Effect"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of magnetometer technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown magnetometer technology: {technology}. Please add it to MagnetometerHWTechnology.")
