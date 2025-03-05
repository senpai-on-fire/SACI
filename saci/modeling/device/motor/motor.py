from claripy import BVS

from ..component import (
    CyberComponentBase,
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentSourceCode,
    CyberComponentBinary,
    CyberAbstractionLevel
)
from saci.modeling.device.component.hardware import HardwareHigh, HardwarePackage, HardwareTechnology

import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================

class MotorHigh(CyberComponentHigh):

    __slots__ = CyberComponentHigh.__slots__ + (
        "is_operational", "fault_detection_flag", "thermal_overload_flag"
    )

    def __init__(self, is_operational=True, fault_detection_flag=False, thermal_overload_flag=False, **kwargs):
        """
        :param is_operational: Indicates if the motor system is functioning.
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

class MotorAlgorithmic(CyberComponentAlgorithmic):

    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "stall_torque", "power_efficiency", "torque_fluctuation_flag",
        "thermal_dissipation_rate", "noise_sensitivity"
    )

    def __init__(
        self, stall_torque=3.0, power_efficiency=0.85, torque_fluctuation_flag=False,
        thermal_dissipation_rate=0.1, noise_sensitivity=0.05, **kwargs
    ):
        """
        :param stall_torque: Maximum torque the motor can exert before stalling.
        :param power_efficiency: Efficiency of converting electrical power into mechanical motion.
        :param torque_fluctuation_flag: Flags abnormal torque variations.
        :param thermal_dissipation_rate: Rate at which the motor dissipates heat.
        :param noise_sensitivity: Sensitivity of the motor to electromagnetic noise (EMI).
        """
        super().__init__(**kwargs)
        self.stall_torque = stall_torque
        self.power_efficiency = power_efficiency
        self.torque_fluctuation_flag = torque_fluctuation_flag
        self.thermal_dissipation_rate = thermal_dissipation_rate
        self.noise_sensitivity = noise_sensitivity

        # Symbolic execution variables for motor control
        self.variables = {
            "rpm": BVS("rpm", 64),
            "current": BVS("motor_current", 64),
            "voltage": BVS("motor_voltage", 64),
            "torque": BVS("motor_torque", 64),
            "power_consumption": BVS("motor_power_consumption", 64),
            "efficiency": BVS("motor_efficiency", 64),
            "temperature": BVS("motor_temperature", 64),
        }

    parameter_types = {
        "stall_torque": float,
        "power_efficiency": float,
        "torque_fluctuation_flag": bool,
        "thermal_dissipation_rate": float,
        "noise_sensitivity": float,
    }


# =================== Hardware Abstraction (Physical Layer) ===================

class MotorHardwareHigh(HardwareHigh):

    def __init__(self, **kwargs):
        super().__init__(modality="motor", **kwargs)


class MotorHardwarePackage(HardwarePackage):

    KNOWN_MOTOR_CHIPS = [
        "ESC32", "T-Motor Alpha", "Hobbywing XRotor", "Castle Creations Phoenix",
        "APD F3", "ODrive Robotics", "Turnigy Multistar"
    ]

    def __init__(self, chip_name, chip_vendor, **kwargs):
        """
        :param chip_name: The name of the motor chip.
        :param chip_vendor: The manufacturer of the motor system.
        """
        super().__init__(chip_name=chip_name, chip_vendor=chip_vendor, **kwargs)
        if chip_name not in self.KNOWN_MOTOR_CHIPS:
            _l.warning(f"Unknown motor chip: {chip_name}. Consider adding it to the known list.")


class MotorHardwareTechnology(HardwareTechnology):

    KNOWN_TECHNOLOGIES = ["Brushless", "Brushed", "Stepper", "Induction", "Hybrid"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of motor technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown motor technology: {technology}. Consider adding it to the known list.")


# =================== Full Motor Component Abstraction (Cyber) ===================

class Motor(CyberComponentBase):

    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Define all abstraction layers
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: MotorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: MotorAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


######################################################    OLD VERSION    ########################################################################

# from ..component import CyberComponentBase, CyberAbstractionLevel, CyberComponentHigh, CyberComponentAlgorithmic

# from claripy import BVS


# class MotorHigh(CyberComponentHigh):
#     __slots__ = CyberComponentHigh.__slots__

#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)


# class MotorAlgorithmic(CyberComponentAlgorithmic):
#     __slots__ = CyberComponentAlgorithmic.__slots__

#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)

#         self.variables["rpm"] = BVS("rpm", 64)

# class Motor(CyberComponentBase):
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.ABSTRACTIONS = {
#             CyberAbstractionLevel.HIGH: MotorHigh(),
#             CyberAbstractionLevel.ALGORITHMIC: MotorAlgorithmic(),
#         }
