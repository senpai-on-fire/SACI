import logging
import claripy

from .sensor import SensorHigh, SensorAlgorithmic, Sensor
from saci.modeling.device.component import HardwarePackage, HardwareTechnology, HardwareHigh
from saci.modeling.device.component import CyberAbstractionLevel, CyberComponentSourceCode, CyberComponentBinary

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================

class BarometerHigh(SensorHigh):

    __slots__ = SensorHigh.__slots__ + ("is_calibrated", "error_flag")

    def __init__(self, is_calibrated=False, error_flag=False, **kwargs):
        """
        :param is_calibrated: Whether the barometer has been calibrated.
        :param error_flag: Flag indicating whether an anomaly or attack has been detected.
        """
        super().__init__(**kwargs)
        self.is_calibrated = is_calibrated
        self.error_flag = error_flag  # Tracks if sensor output is compromised


# =================== Algorithmic Abstraction ===================

class BarometerAlgorithmic(SensorAlgorithmic):

    __slots__ = SensorAlgorithmic.__slots__ + (
        "precision_bits",
        "bias_drift",
        "quantization_noise",
        "error_flag",
    )

    def __init__(self, precision_bits=16, bias_drift=0.05, quantization_noise=0.01, **kwargs):
        """
        :param precision_bits: Bit resolution for atmospheric pressure readings.
        :param bias_drift: Expected drift in pressure readings (useful for attack modeling).
        :param quantization_noise: Noise introduced by digital resolution.
        """
        super().__init__(**kwargs)
        self.precision_bits = precision_bits
        self.bias_drift = bias_drift
        self.quantization_noise = quantization_noise
        self.error_flag = claripy.BVS("baro_error_flag", 1)  # Tracks anomalies

        # Store atmospheric pressure as a symbolic bit-vector
        self.variables["pressure_reading"] = claripy.BVS("baro_pressure", precision_bits)

        # Track drift and noise influence
        self.variables["bias_drift"] = claripy.BVS("baro_bias_drift", 32)
        self.variables["quantization_noise"] = claripy.BVS("baro_quantization_noise", 32)


# =================== Full Sensor Abstraction ===================

class Barometer(Sensor):

    __slots__ = ("precision_bits", "bias_drift", "quantization_noise", "ABSTRACTIONS")

    def __init__(self, precision_bits=16, bias_drift=0.05, quantization_noise=0.01, **kwargs):
        """
        :param precision_bits: Bit resolution for pressure readings.
        :param bias_drift: Barometric bias drift (affects accuracy over time).
        :param quantization_noise: Noise due to digital resolution limitations.
        """
        super().__init__(**kwargs)

        # Instantiate high and algorithmic abstractions
        high_abstraction = BarometerHigh()
        algo_abstraction = BarometerAlgorithmic(
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

class BarometerHWHigh(HardwareHigh):

    def __init__(self, **kwargs):
        super().__init__(modality="barometer", **kwargs)


class BarometerHWPackage(HardwarePackage):

    KNOWN_CHIP_NAMES = [
        "BMP180", "BMP280", "BMP388", "MS5611", "LPS22HB", "LPS25HB", "DPS310"
    ]

    def __init__(self, baro_name, baro_vendor, **kwargs):
        """
        :param baro_name: The name of the barometer chip.
        :param baro_vendor: The manufacturer of the barometer chip.
        """
        super().__init__(chip_name=baro_name, chip_vendor=baro_vendor, **kwargs)
        if baro_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(f"Unknown barometer chip name: {baro_name}. Please add it to BarometerHWPackage.")


class BarometerHWTechnology(HardwareTechnology):

    KNOWN_TECHNOLOGIES = ["MEMS", "Silicon Piezoresistive", "Capacitive", "Optical"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of barometer technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown barometer technology: {technology}. Please add it to BarometerHWTechnology.")
