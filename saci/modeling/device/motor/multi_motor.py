from typing import List
from claripy import BVS

from ..component import (
    CyberAbstractionLevel,
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary
)
from saci.modeling.device.component.hardware import HardwareHigh, HardwarePackage, HardwareTechnology
from .motor import MotorHigh, MotorAlgorithmic, Motor

import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================

class MultiMotorHigh(MotorHigh):

    __slots__ = MotorHigh.__slots__ + (
        "motors", "is_operational", "fault_detection_flag", "load_imbalance_flag"
    )

    def __init__(self, motors=None, is_operational=True, fault_detection_flag=False, load_imbalance_flag=False, **kwargs):
        """
        :param motors: List of individual motors.
        :param is_operational: Indicates if the multi-motor system is functioning.
        :param fault_detection_flag: Detects any motor failure conditions.
        :param load_imbalance_flag: Flags an imbalance in power/load distribution across motors.
        """
        super().__init__(**kwargs)
        self.motors: List[MotorHigh] = motors or []
        self.is_operational = is_operational
        self.fault_detection_flag = fault_detection_flag
        self.load_imbalance_flag = load_imbalance_flag  # Helps detect uneven power/load distribution.

    @property
    def motor_cnt(self):
        return len(self.motors)

    parameter_types = {
        "is_operational": bool,
        "fault_detection_flag": bool,
        "load_imbalance_flag": bool,
    }


# =================== Algorithmic Abstraction (Cyber) ===================

class MultiMotorAlgorithmic(MotorAlgorithmic):

    __slots__ = MotorAlgorithmic.__slots__ + (
        "motors", "power_distribution_ratio", "torque_fluctuation_flag",
        "thermal_safety_limit", "inter_motor_sync_error"
    )

    def __init__(
        self, motors=None, power_distribution_ratio=1.0, torque_fluctuation_flag=False,
        thermal_safety_limit=75.0, inter_motor_sync_error=0.05, **kwargs
    ):
        """
        :param motors: List of individual motors.
        :param power_distribution_ratio: Ratio of power distribution across motors (1.0 = balanced).
        :param torque_fluctuation_flag: Flags anomalies in torque behavior.
        :param thermal_safety_limit: Temperature threshold (°C) before motors enter thermal safety mode.
        :param inter_motor_sync_error: Measures synchronization errors across multiple motors.
        """
        super().__init__(**kwargs)
        self.motors: List[MotorAlgorithmic] = motors or []
        self.power_distribution_ratio = power_distribution_ratio
        self.torque_fluctuation_flag = torque_fluctuation_flag
        self.thermal_safety_limit = thermal_safety_limit
        self.inter_motor_sync_error = inter_motor_sync_error

        # Symbolic execution variables for multi-motor performance
        self.variables = {
            "total_rpm": self.rpm,
            "power_efficiency": BVS("motor_power_efficiency", 64),
            "heat_generation": BVS("motor_heat_generation", 64),
            "power_consumption": BVS("motor_power_consumption", 64),
        }

    @property
    def rpm(self):
        """
        Calculates the total RPM of the multi-motor system.
        """
        total_rpm = BVS("rpm", 64)
        for motor in self.motors:
            total_rpm += motor.variables["rpm"]

        return total_rpm

    parameter_types = {
        "power_distribution_ratio": float,
        "torque_fluctuation_flag": bool,
        "thermal_safety_limit": float,
        "inter_motor_sync_error": float,
    }


# =================== Hardware Abstraction (Physical Layer) ===================

class MultiMotorHardwareHigh(HardwareHigh):

    def __init__(self, **kwargs):
        super().__init__(modality="multi-motor", **kwargs)


class MultiMotorHardwarePackage(HardwarePackage):

    KNOWN_MOTOR_CHIPS = [
        "ESC32", "T-Motor Alpha", "Hobbywing XRotor", "Castle Creations Phoenix",
        "APD F3", "ODrive Robotics", "Turnigy Multistar"
    ]

    def __init__(self, chip_name, chip_vendor, **kwargs):
        """
        :param chip_name: The name of the multi-motor system chip.
        :param chip_vendor: The manufacturer of the motor system.
        """
        super().__init__(chip_name=chip_name, chip_vendor=chip_vendor, **kwargs)
        if chip_name not in self.KNOWN_MOTOR_CHIPS:
            _l.warning(f"Unknown motor chip: {chip_name}. Consider adding it to the known list.")


class MultiMotorHardwareTechnology(HardwareTechnology):

    KNOWN_TECHNOLOGIES = ["Brushless", "Brushed", "Stepper", "Induction", "Hybrid"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of motor technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown motor technology: {technology}. Consider adding it to the known list.")


# =================== Full Multi-Motor Component Abstraction (Cyber) ===================

class MultiMotor(Motor):

    __slots__ = ("ABSTRACTIONS", "variables", "motors")

    def __init__(self, motors=None, **kwargs):
        """
        :param motors: List of motors composing the system.
        """
        super().__init__(**kwargs)

        self.motors = motors or []

        # Define all abstraction layers
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: MultiMotorHigh(motors=self.motors),
            CyberAbstractionLevel.ALGORITHMIC: MultiMotorAlgorithmic(motors=self.motors),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
