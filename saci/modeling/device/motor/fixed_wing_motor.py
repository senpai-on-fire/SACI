import logging
from claripy import BVS

from ..component import (
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
    CyberAbstractionLevel,
)
from saci.modeling.device.component.hardware import (
    HardwareHigh,
    HardwarePackage,
    HardwareTechnology,
)

from .multi_motor import MultiMotorHigh, MultiMotorAlgorithmic

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class FixedWingMotorHigh(MultiMotorHigh):
    __slots__ = MultiMotorHigh.__slots__ + (
        "is_operational",
        "overload_flag",
        "rpm_variation_flag",
        "vibration_detected_flag",
    )

    def __init__(
        self,
        is_operational=True,
        overload_flag=False,
        rpm_variation_flag=False,
        vibration_detected_flag=False,
        **kwargs,
    ):
        """
        :param is_operational: Indicates whether the motor is functional.
        :param overload_flag: Indicates excessive current/load conditions.
        :param rpm_variation_flag: Detects abnormal RPM behavior.
        :param vibration_detected_flag: Flags mechanical imbalance or wear.
        """
        super().__init__(**kwargs)
        self.is_operational = is_operational
        self.overload_flag = overload_flag
        self.rpm_variation_flag = rpm_variation_flag
        self.vibration_detected_flag = vibration_detected_flag

    parameter_types = {
        "is_operational": bool,
        "overload_flag": bool,
        "rpm_variation_flag": bool,
        "vibration_detected_flag": bool,
    }


# =================== Algorithmic Abstraction (Cyber) ===================


class FixedWingMotorAlgorithmic(MultiMotorAlgorithmic):
    __slots__ = MultiMotorAlgorithmic.__slots__ + (
        "propeller_pitch",
        "motor_rpm",
        "thrust_margin",
    )

    def __init__(self, propeller_pitch=10.0, motor_rpm=8000, thrust_margin=0.95, **kwargs):
        """
        :param propeller_pitch: Propeller pitch in inches.
        :param motor_rpm: Nominal motor RPM under standard load.
        :param thrust_margin: Remaining thrust capacity margin (0-1).
        """
        super().__init__(**kwargs)
        self.propeller_pitch = propeller_pitch
        self.motor_rpm = motor_rpm
        self.thrust_margin = thrust_margin

        self.variables = {
            "fixedwing_thrust": BVS("fixedwing_thrust", 64),
            "fixedwing_rpm": BVS("fixedwing_rpm", 64),
            "propeller_efficiency": BVS("propeller_efficiency", 64),
            "motor_torque": BVS("motor_torque", 64),
            "thrust_margin_index": BVS("thrust_margin_index", 64),
        }

    parameter_types = {
        "propeller_pitch": float,
        "motor_rpm": int,
        "thrust_margin": float,
    }


# =================== Hardware Abstraction (Physical Layer) ===================


class FixedWingMotorHardwareHigh(HardwareHigh):
    def __init__(self, **kwargs):
        super().__init__(modality="fixed-wing motor", **kwargs)


class FixedWingMotorHardwarePackage(HardwarePackage):
    KNOWN_FIXEDWING_MOTORS = [
        "Turnigy Aerodrive SK3",
        "Scorpion SII",
        "E-flite Power 10",
        "O.S. Max 61FX",
        "RimFire 35-48-850",
        "Dualsky XM5060",
    ]

    def __init__(self, chip_name, chip_vendor, **kwargs):
        """
        :param chip_name: Motor model identifier.
        :param chip_vendor: Manufacturer name.
        """
        super().__init__(chip_name=chip_name, chip_vendor=chip_vendor, **kwargs)
        if chip_name not in self.KNOWN_FIXEDWING_MOTORS:
            _l.warning(f"Unknown fixed-wing motor: {chip_name}. Consider adding it to the known list.")


class FixedWingMotorTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["Brushless", "Brushed", "Outrunner", "Inrunner", "Electric", "Gasoline"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Technology used for propulsion (e.g., electric, gasoline).
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown motor technology: {technology}. Consider adding it to the known list.")


# =================== Full Fixed-Wing Motor Component (Cyber) ===================


class FixedWingMotor(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "variables")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: FixedWingMotorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: FixedWingMotorAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
