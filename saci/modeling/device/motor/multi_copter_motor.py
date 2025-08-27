from claripy import BVS

from saci.modeling.device.motor.motor import Motor

from ..component import (
    CyberComponentSourceCode,
    CyberComponentBinary,
    CyberAbstractionLevel,
)
from saci.modeling.device.component.hardware import HardwareHigh, HardwarePackage, HardwareTechnology
from .multi_motor import MultiMotorHigh, MultiMotorAlgorithmic

import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class MultiCopterMotorHigh(MultiMotorHigh):
    __slots__ = MultiMotorHigh.__slots__ + (
        "is_operational",
        "fault_detection_flag",
        "torque_instability_flag",
        "load_imbalance_flag",
    )

    def __init__(
        self,
        is_operational=True,
        fault_detection_flag=False,
        torque_instability_flag=False,
        load_imbalance_flag=False,
        **kwargs,
    ):
        """
        :param is_operational: Indicates if the multicopter motor system is functioning.
        :param fault_detection_flag: Detects any motor failure conditions.
        :param torque_instability_flag: Detects abnormal torque variations.
        :param load_imbalance_flag: Ensures equal power/load distribution across rotors.
        """
        super().__init__(**kwargs)
        self.is_operational = is_operational
        self.fault_detection_flag = fault_detection_flag
        self.torque_instability_flag = torque_instability_flag  # Helps detect unusual torque changes.
        self.load_imbalance_flag = load_imbalance_flag  # Ensures proper load distribution.

    parameter_types = {
        "is_operational": bool,
        "fault_detection_flag": bool,
        "torque_instability_flag": bool,
        "load_imbalance_flag": bool,
    }


# =================== Algorithmic Abstraction (Cyber) ===================


class MultiCopterMotorAlgorithmic(MultiMotorAlgorithmic):
    __slots__ = MultiMotorAlgorithmic.__slots__ + ("thrust_efficiency", "power_distribution_ratio", "stability_margin")

    def __init__(self, thrust_efficiency=0.85, power_distribution_ratio=1.0, stability_margin=0.9, **kwargs):
        """
        :param thrust_efficiency: Efficiency of converting power into lift.
        :param power_distribution_ratio: Ensures equal power distribution across rotors.
        :param stability_margin: Measures system stability against disturbances.
        """
        super().__init__(**kwargs)
        self.thrust_efficiency = thrust_efficiency
        self.power_distribution_ratio = power_distribution_ratio
        self.stability_margin = stability_margin

        # Symbolic execution variables for flight control dynamics
        self.variables = {
            "lift": BVS("lift", 64),
            "yaw": BVS("yaw", 64),
            "pitch": BVS("pitch", 64),
            "roll": BVS("roll", 64),
            "power_efficiency": BVS("motor_power_efficiency", 64),
            "stability_index": BVS("motor_stability_index", 64),
        }

    parameter_types = {
        "thrust_efficiency": float,
        "power_distribution_ratio": float,
        "stability_margin": float,
    }


# =================== Hardware Abstraction (Physical Layer) ===================


class MultiCopterMotorHardwareHigh(HardwareHigh):
    def __init__(self, **kwargs):
        super().__init__(modality="multi-rotor motor", **kwargs)


class MultiCopterMotorHardwarePackage(HardwarePackage):
    KNOWN_MOTOR_CHIPS = [
        "T-Motor U7",
        "KDE 7208XF",
        "SunnySky V4006",
        "EMAX MT2213",
        "Turnigy Multistar",
        "DJI 2312",
        "XING-E Pro 2207",
    ]

    def __init__(self, chip_name, chip_vendor, **kwargs):
        """
        :param chip_name: The name of the multicopter motor chip.
        :param chip_vendor: The manufacturer of the motor system.
        """
        super().__init__(chip_name=chip_name, chip_vendor=chip_vendor, **kwargs)
        if chip_name not in self.KNOWN_MOTOR_CHIPS:
            _l.warning(f"Unknown multicopter motor chip: {chip_name}. Consider adding it to the known list.")


class MultiCopterMotorHardwareTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["Brushless", "Brushed", "Hybrid", "Direct Drive", "Coaxial"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of multicopter motor technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown multicopter motor technology: {technology}. Consider adding it to the known list.")


# =================== Full MultiCopter Motor Component Abstraction (Cyber) ===================


class MultiCopterMotor(Motor):
    __slots__ = ("ABSTRACTIONS", "variables")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Define all abstraction layers
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: MultiCopterMotorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: MultiCopterMotorAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
