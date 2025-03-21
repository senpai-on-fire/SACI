import logging
from ..component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
    CyberAbstractionLevel,
)
from saci.modeling.device.component.hardware import HardwareHigh, HardwarePackage, HardwareTechnology
from claripy import BVS

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class ServoHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("is_operational", "fault_detection_flag", "thermal_overload_flag")

    def __init__(self, is_operational=True, fault_detection_flag=False, thermal_overload_flag=False, **kwargs):
        """
        :param is_operational: Indicates if the servo motor is functioning.
        :param fault_detection_flag: Tracks detected motor faults (mechanical/electrical).
        :param thermal_overload_flag: Detects overheating due to excessive load or attack.
        """
        super().__init__(**kwargs)
        self.is_operational = is_operational
        self.fault_detection_flag = fault_detection_flag
        self.thermal_overload_flag = thermal_overload_flag  # Detects possible thermal-related failures.

    parameter_types = {
        "is_operational": bool,
        "fault_detection_flag": bool,
        "thermal_overload_flag": bool,
    }


# =================== Algorithmic Abstraction (Cyber) ===================


class ServoAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "stall_torque",
        "holding_torque",
        "backlash_error",
        "noise_sensitivity",
        "efficiency_drop_rate",
        "torque_anomaly_flag",
    )

    def __init__(
        self,
        stall_torque=2.5,
        holding_torque=2.0,
        backlash_error=0.05,
        noise_sensitivity=0.1,
        efficiency_drop_rate=0.02,
        torque_anomaly_flag=False,
        **kwargs,
    ):
        """
        :param stall_torque: Maximum torque the servo can exert before stalling.
        :param holding_torque: Torque required to maintain position under load.
        :param backlash_error: Mechanical error in angular position due to gear play.
        :param noise_sensitivity: Sensitivity of servo to electrical noise (e.g., EMI).
        :param efficiency_drop_rate: Rate of efficiency degradation over time.
        :param torque_anomaly_flag: Flag for abnormal torque variations (e.g., attack or jam).
        """
        super().__init__(**kwargs)
        self.stall_torque = stall_torque
        self.holding_torque = holding_torque
        self.backlash_error = backlash_error
        self.noise_sensitivity = noise_sensitivity
        self.efficiency_drop_rate = efficiency_drop_rate
        self.torque_anomaly_flag = torque_anomaly_flag  # Detects unusual torque variations.

        # Symbolic Variables for Servo Motor Modeling
        self.variables = {
            "voltage": BVS("servo_voltage", 64),
            "current": BVS("servo_current", 64),
            "torque": BVS("servo_torque", 64),
            "angle": BVS("servo_angle", 64),
            "speed": BVS("servo_speed", 64),
            "position": BVS("servo_position", 64),
            "temperature": BVS("servo_temperature", 64),
            "power": BVS("servo_power", 64),
            "efficiency": BVS("servo_efficiency", 64),
        }

    parameter_types = {
        "stall_torque": float,
        "holding_torque": float,
        "backlash_error": float,
        "noise_sensitivity": float,
        "efficiency_drop_rate": float,
        "torque_anomaly_flag": bool,
    }


# =================== Hardware Abstraction (Physical Layer) ===================


class ServoHardwareHigh(HardwareHigh):
    def __init__(self, **kwargs):
        super().__init__(modality="servo_motor", **kwargs)


class ServoHardwarePackage(HardwarePackage):
    KNOWN_SERVO_CHIPS = [
        "HS-645MG",
        "MG996R",
        "Dynamixel AX-12A",
        "Savox SC-1256TG",
        "Futaba S3003",
        "TowerPro SG90",
        "Hitec HS-805BB",
    ]

    def __init__(self, chip_name, chip_vendor, **kwargs):
        """
        :param chip_name: The name of the servo motor chip.
        :param chip_vendor: The manufacturer of the servo motor.
        """
        super().__init__(chip_name=chip_name, chip_vendor=chip_vendor, **kwargs)
        if chip_name not in self.KNOWN_SERVO_CHIPS:
            _l.warning(f"Unknown servo chip: {chip_name}. Consider adding it to the known list.")


class ServoHardwareTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["PWM-Controlled", "Brushless", "Coreless", "Digital", "Analog"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of servo motor technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown servo technology: {technology}. Consider adding it to the known list.")


# =================== Full Servo Component Abstraction (Cyber) ===================


class Servo(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "variables")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Define all abstraction layers
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ServoHigh(),
            CyberAbstractionLevel.ALGORITHMIC: ServoAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
