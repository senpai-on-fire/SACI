import logging
import claripy

from .sensor import SensorHigh, SensorAlgorithmic, Sensor
from saci.modeling.device.component import HardwarePackage, HardwareTechnology
from saci.modeling.device.component import CyberAbstractionLevel, CyberComponentSourceCode, CyberComponentBinary

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================


class AccelerometerHigh(SensorHigh):
    __slots__ = SensorHigh.__slots__ + ("is_calibrated", "error_flag")

    def __init__(self, is_calibrated=False, error_flag=False, **kwargs):
        """
        :param is_calibrated: Whether the accelerometer is calibrated.
        :param error_flag: Flag indicating whether an anomaly or attack has been detected.
        """
        super().__init__(**kwargs)
        self.is_calibrated = is_calibrated
        self.error_flag = error_flag  # Tracks if the sensor output is compromised

        # High-level state variables
        self.variables["is_calibrated"] = claripy.BVS("accel_is_calibrated", 1)
        self.variables["motion_detected"] = claripy.BVS("accel_motion_detected", 1)


# =================== Algorithmic Abstraction ===================


class AccelerometerAlgorithmic(SensorAlgorithmic):
    __slots__ = SensorAlgorithmic.__slots__ + (
        "precision_bits",
        "bias_drift",
        "quantization_noise",
        "error_flag",
    )

    def __init__(self, precision_bits=14, bias_drift=0.05, quantization_noise=0.01, **kwargs):
        """
        :param precision_bits: Bit resolution of accelerometer readings.
        :param bias_drift: Expected drift in accelerometer readings (useful for attack modeling).
        :param quantization_noise: Approximation error due to limited bit precision.
        """
        super().__init__(**kwargs)
        self.precision_bits = precision_bits
        self.bias_drift = bias_drift
        self.quantization_noise = quantization_noise

        # Store separate X, Y, Z readings with configurable precision
        self.variables["accel_x"] = claripy.BVS("accel_x", precision_bits)
        self.variables["accel_y"] = claripy.BVS("accel_y", precision_bits)
        self.variables["accel_z"] = claripy.BVS("accel_z", precision_bits)

        # Optionally add sensor-specific attributes (bias, noise, scale factor, drift, etc.)
        self.variables["bias"] = claripy.BVS("accel_bias", precision_bits)
        self.variables["noise"] = claripy.BVS("accel_noise", precision_bits)
        self.variables["scale_factor"] = claripy.BVS("accel_scale_factor", precision_bits)
        self.variables["temperature_effect"] = claripy.BVS("accel_temp_effect", precision_bits)


# =================== Full Sensor Abstraction ===================


class Accelerometer(Sensor):
    __slots__ = ("precision_bits", "bias_drift", "quantization_noise", "ABSTRACTIONS")

    def __init__(self, precision_bits=14, bias_drift=0.05, quantization_noise=0.01, **kwargs):
        """
        :param precision_bits: Bit resolution for data representation.
        :param bias_drift: Accelerometer bias drift (affects accuracy over time).
        :param quantization_noise: Noise due to digital resolution limitations.
        """
        super().__init__(**kwargs)

        high_abstraction = AccelerometerHigh()
        algo_abstraction = AccelerometerAlgorithmic(
            precision_bits=precision_bits,
            bias_drift=bias_drift,
            quantization_noise=quantization_noise,
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== Hardware Abstractions ===================


class AccelerometerHardware(Accelerometer):
    """
    Hardware-level accelerometer model, capturing physical/mechanical/electrical attributes.
    """

    __slots__ = Sensor.__slots__

    def __init__(
        self,
        i2c_address=0x68,
        spi_channel=0,
        resonant_frequency=None,  # in Hz or kHz
        damping_ratio=None,  # or quality factor
        acoustic_isolation=False,  # any mechanical shielding
        max_acoustic_input=None,  # amplitude limit before saturation
        **kwargs,
    ):
        """
        :param i2c_address: I2C address for communication.
        :param spi_channel: SPI channel if using SPI-based sensors.
        :param resonant_frequency: Natural frequency where sensor resonates (e.g., 19 kHz).
        :param damping_ratio: Determines sharpness of resonance peak. Lower => more vulnerable.
        :param acoustic_isolation: Whether there's mechanical shielding or damping.
        :param max_acoustic_input: Threshold beyond which the sensor saturates or clips.
        """
        super().__init__(**kwargs)

        self.i2c_address = i2c_address
        self.spi_channel = spi_channel

        # Real-world physical attributes
        self.resonant_frequency = resonant_frequency
        self.damping_ratio = damping_ratio
        self.acoustic_isolation = acoustic_isolation
        self.max_acoustic_input = max_acoustic_input

        self.variables = {}

        # Simulated hardware register values
        self.variables["hardware_status"] = claripy.BVS("accel_hw_status", 8)  # 8-bit status register
        self.variables["hardware_config"] = claripy.BVS("accel_hw_config", 16)  # 16-bit config register


class AccelerometerHWPackage(HardwarePackage):
    KNOWN_CHIP_NAMES = [
        "MPU6050",
        "MPU6500",
        "MPU9250",
        "ADXL345",
        "LIS3DH",
        "LSM9DS1",
        "ICM-20948",
        "BMI055",
        "BMI160",
        "ICM-20690",
        "MPU6000",
        "LSM6DSL",
    ]

    def __init__(self, accel_name, accel_vendor, **kwargs):
        """
        :param accel_name: The name of the accelerometer chip.
        :param accel_vendor: The manufacturer of the accelerometer chip.
        """
        super().__init__(chip_name=accel_name, chip_vendor=accel_vendor, **kwargs)
        if accel_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(f"Unknown accelerometer chip name: {accel_name}. Please add it to AccelerometerHWPackage.")


class AccelerometerHWTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["MEMS", "Piezoelectric", "Capacitive", "Resonant"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of accelerometer technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown accelerometer technology: {technology}. Please add it to AccelerometerHWTechnology.")
