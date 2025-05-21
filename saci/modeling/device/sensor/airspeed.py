import logging
import claripy

from .sensor import SensorHigh, SensorAlgorithmic, Sensor
from saci.modeling.device.component import HardwarePackage, HardwareTechnology, HardwareHigh
from saci.modeling.device.component import CyberAbstractionLevel, CyberComponentSourceCode, CyberComponentBinary

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================

class AirspeedHigh(SensorHigh):
    __slots__ = SensorHigh.__slots__ + ("is_calibrated", "error_flag")

    def __init__(self, is_calibrated=False, error_flag=False, **kwargs):
        """
        :param is_calibrated: Whether the airspeed sensor has been calibrated.
        :param error_flag: Indicates whether an anomaly or attack has been detected.
        """
        super().__init__(**kwargs)
        self.is_calibrated = is_calibrated
        self.error_flag = error_flag  # Tracks if sensor output is compromised

# =================== Algorithmic Abstraction ===================

class AirspeedAlgorithmic(SensorAlgorithmic):
    __slots__ = SensorAlgorithmic.__slots__ + (
        "precision_bits",
        "bias_offset",
        "noise_stddev",
        "error_flag",
    )

    def __init__(self, precision_bits=16, bias_offset=0.1, noise_stddev=0.05, **kwargs):
        """
        :param precision_bits: Bit resolution for airspeed measurements.
        :param bias_offset: Systematic error or drift in airspeed.
        :param noise_stddev: Standard deviation of measurement noise.
        """
        super().__init__(**kwargs)
        self.precision_bits = precision_bits
        self.bias_offset = bias_offset
        self.noise_stddev = noise_stddev
        self.error_flag = claripy.BVS("airspeed_error_flag", 1)

        # Symbolic variables representing internal states
        self.variables["airspeed_reading"] = claripy.BVS("airspeed_value", precision_bits)
        self.variables["bias_offset"] = claripy.BVS("airspeed_bias", 32)
        self.variables["noise_stddev"] = claripy.BVS("airspeed_noise", 32)

# =================== Full Sensor Abstraction ===================

class AirspeedSensor(Sensor):
    __slots__ = ("precision_bits", "bias_offset", "noise_stddev", "ABSTRACTIONS")

    def __init__(self, precision_bits=16, bias_offset=0.1, noise_stddev=0.05, **kwargs):
        """
        :param precision_bits: Bit resolution of the airspeed signal.
        :param bias_offset: Airspeed bias error.
        :param noise_stddev: Random noise level in the sensor.
        """
        super().__init__(**kwargs)

        high_abstraction = AirspeedHigh()
        algo_abstraction = AirspeedAlgorithmic(
            precision_bits=precision_bits,
            bias_offset=bias_offset,
            noise_stddev=noise_stddev,
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

# =================== Hardware Abstractions ===================

class AirspeedHWHigh(HardwareHigh):
    def __init__(self, **kwargs):
        super().__init__(modality="airspeed", **kwargs)

class AirspeedHWPackage(HardwarePackage):
    KNOWN_CHIP_NAMES = ["MS4525DO", "DLHR", "MPXV7002DP", "MS5525DSO", "SDP810"]

    def __init__(self, airspeed_name, airspeed_vendor, **kwargs):
        """
        :param airspeed_name: The chip name of the airspeed sensor.
        :param airspeed_vendor: Manufacturer name.
        """
        super().__init__(chip_name=airspeed_name, chip_vendor=airspeed_vendor, **kwargs)
        if airspeed_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(f"Unknown airspeed chip name: {airspeed_name}. Please add it to AirspeedHWPackage.")

class AirspeedHWTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["MEMS", "Thermal", "Pitot-Tube", "Ultrasonic"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: The sensing principle used for measuring airspeed.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown airspeed technology: {technology}. Please add it to AirspeedHWTechnology.")
