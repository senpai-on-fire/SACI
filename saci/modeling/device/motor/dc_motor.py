import logging

from claripy import BVS

from saci.modeling.device.component.hardware import HardwareHigh, HardwarePackage, HardwareTechnology
from saci.modeling.device.motor.motor import Motor

from ..component import (
    CyberAbstractionLevel,
    CyberComponentAlgorithmic,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
)

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class DCMotorHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("is_operational", "fault_detection_flag", "thermal_overload_flag")

    def __init__(self, is_operational=True, fault_detection_flag=False, thermal_overload_flag=False, **kwargs):
        """
        :param is_operational: Indicates if the DC motor system is functioning.
        :param fault_detection_flag: Detects any motor failure conditions.
        :param thermal_overload_flag: Flags overheating conditions.
        """
        super().__init__(**kwargs)
        self.is_operational = is_operational
        self.fault_detection_flag = fault_detection_flag
        self.thermal_overload_flag = thermal_overload_flag  # Detects overheating conditions.

    parameter_types = {
        "is_operational": bool,
        "fault_detection_flag": bool,
        "thermal_overload_flag": bool,
    }


# =================== Algorithmic Abstraction (Cyber) ===================


class DCMotorAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "stall_torque",
        "power_efficiency",
        "torque_anomaly_flag",
        "thermal_dissipation_rate",
        "noise_sensitivity",
    )

    def __init__(
        self,
        stall_torque=3.5,
        power_efficiency=0.88,
        torque_anomaly_flag=False,
        thermal_dissipation_rate=0.12,
        noise_sensitivity=0.06,
        **kwargs,
    ):
        """
        :param stall_torque: Maximum torque the motor can exert before stalling.
        :param power_efficiency: Efficiency in converting electrical power into mechanical motion.
        :param torque_anomaly_flag: Flags abnormal torque variations.
        :param thermal_dissipation_rate: Rate at which the motor dissipates heat.
        :param noise_sensitivity: Sensitivity of the motor to electromagnetic noise (EMI).
        """
        super().__init__(**kwargs)
        self.stall_torque = stall_torque
        self.power_efficiency = power_efficiency
        self.torque_anomaly_flag = torque_anomaly_flag
        self.thermal_dissipation_rate = thermal_dissipation_rate
        self.noise_sensitivity = noise_sensitivity

        # Symbolic execution variables for DC motor modeling
        self.variables = {
            "voltage": BVS("dc_motor_voltage", 64),
            "current": BVS("dc_motor_current", 64),
            "torque": BVS("dc_motor_torque", 64),
            "speed": BVS("dc_motor_speed", 64),
            "position": BVS("dc_motor_position", 64),
            "temperature": BVS("dc_motor_temperature", 64),
            "power": BVS("dc_motor_power", 64),
            "efficiency": BVS("dc_motor_efficiency", 64),
            "heat_generation": BVS("dc_motor_heat_generation", 64),
        }

    parameter_types = {
        "stall_torque": float,
        "power_efficiency": float,
        "torque_anomaly_flag": bool,
        "thermal_dissipation_rate": float,
        "noise_sensitivity": float,
    }


# =================== Hardware Abstraction (Physical Layer) ===================


class DCMotorHardwareHigh(HardwareHigh):
    def __init__(self, **kwargs):
        super().__init__(modality="dc_motor", **kwargs)


class DCMotorHardwarePackage(HardwarePackage):
    KNOWN_MOTOR_CHIPS = [
        "Pololu 37D",
        "Maxon RE-40",
        "Bühler DCX-22",
        "Faulhaber 2657",
        "RS775",
        "Mabuchi 550",
        "Dynamixel MX-28",
    ]

    def __init__(self, chip_name, chip_vendor, **kwargs):
        """
        :param chip_name: The name of the DC motor chip.
        :param chip_vendor: The manufacturer of the DC motor.
        """
        super().__init__(chip_name=chip_name, chip_vendor=chip_vendor, **kwargs)
        if chip_name not in self.KNOWN_MOTOR_CHIPS:
            _l.warning(f"Unknown DC motor chip: {chip_name}. Consider adding it to the known list.")


class DCMotorHardwareTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["Brushed", "Brushless", "Coreless", "Stepper", "Servo"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of DC motor technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown DC motor technology: {technology}. Consider adding it to the known list.")


# =================== Full DC Motor Component Abstraction (Cyber) ===================


class DCMotor(Motor):
    __slots__ = ("ABSTRACTIONS", "variables")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Define all abstraction layers
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: DCMotorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: DCMotorAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
