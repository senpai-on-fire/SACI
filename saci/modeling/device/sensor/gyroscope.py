import logging
import claripy

# Adjust these imports to match your actual project structure:
from .sensor import SensorHigh, SensorAlgorithmic, Sensor
from saci.modeling.device.component import HardwarePackage, HardwareTechnology, HardwareHigh
from saci.modeling.device.component import CyberAbstractionLevel, CyberComponentSourceCode, CyberComponentBinary

_l = logging.getLogger(__name__)


class GyroscopeHigh(SensorHigh):
    __slots__ = SensorHigh.__slots__ + ("is_calibrated", "error_flag")

    def __init__(self, is_calibrated=False, error_flag=False, **kwargs):
        """
        :param is_calibrated: Whether the gyroscope has been calibrated.
        :param error_flag: Flag indicating whether an anomaly or attack has been detected.
        """
        super().__init__(**kwargs)
        self.is_calibrated = is_calibrated
        self.error_flag = error_flag  # Tracks if the sensor output is compromised


class GyroscopeAlgorithmic(SensorAlgorithmic):
    __slots__ = SensorAlgorithmic.__slots__ + (
        "precision_bits",
        "bias_drift",
        "quantization_noise",
        "error_flag",
    )

    def __init__(self, precision_bits=14, bias_drift=0.05, quantization_noise=0.01, **kwargs):
        """
        :param precision_bits: Bit resolution of gyroscope readings.
        :param bias_drift: Expected drift in the gyroscope (useful for attack modeling).
        :param quantization_noise: Approximation error due to limited bit precision.
        :param error_flag: Flag to track whether data integrity is compromised.
        """
        super().__init__(**kwargs)
        self.precision_bits = precision_bits
        self.bias_drift = bias_drift
        self.quantization_noise = quantization_noise
        self.error_flag = claripy.BVS("gyro_error_flag", 1)  # Tracks anomalies

        # Store sensor readings in a single bitvector
        self.variables["readings"] = claripy.BVS("gyro_readings", precision_bits * 6)

        # Track sensor drift and noise influence
        self.variables["bias_drift"] = claripy.BVS("gyro_bias_drift", 32)
        self.variables["quantization_noise"] = claripy.BVS("gyro_quantization_noise", 32)


class Gyroscope(Sensor):
    __slots__ = ("precision_bits", "bias_drift", "quantization_noise", "ABSTRACTIONS")

    def __init__(self, precision_bits=14, bias_drift=0.05, quantization_noise=0.01, **kwargs):
        """
        :param precision_bits: Bit resolution for data representation.
        :param bias_drift: Gyroscope bias drift (affects accuracy over time).
        :param quantization_noise: Noise due to digital resolution limitations.
        """
        super().__init__(**kwargs)

        # Instantiate high and algorithmic abstractions with vulnerability parameters
        high_abstraction = GyroscopeHigh()
        algo_abstraction = GyroscopeAlgorithmic(
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


class GyroscopeHWHigh(HardwareHigh):
    def __init__(self, **kwargs):
        super().__init__(modality="gyroscope", **kwargs)


class GyroscopeHWPackage(HardwarePackage):
    KNOWN_CHIP_NAMES = [
        "L3G4200D",
        "L3GD20",
        "LSM330",
        "LPR5150AL",
        "LPY503AL",
        "MPU3050",
        "MPU6000",
        "MPU6050",
        "MPU6500",
        "MPU9150",
        "MPU9250",
        "IMU3000",
        "ITG3200",
        "IXZ650",
        "ADXRS610",
        "ENC-03MB",
    ]

    def __init__(self, gyro_name, gyro_vendor, **kwargs):
        """
        :param gyro_name: The name of the gyroscope chip.
        :param gyro_vendor: The manufacturer of the gyroscope chip.
        """
        super().__init__(chip_name=gyro_name, chip_vendor=gyro_vendor, **kwargs)
        if gyro_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(f"Unknown gyroscope chip name: {gyro_name}. Please add it to GyroscopeHWPackage.")


class GyroscopeHWTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["MEMS", "Fiber Optic", "Inertial"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of gyroscope technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown gyroscope technology: {technology}. Please add it to GyroscopeHWTechnology.")
