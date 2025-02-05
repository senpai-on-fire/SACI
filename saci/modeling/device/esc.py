from typing import Optional
from saci.modeling.device.component import (
    CyberComponentBase,
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentSourceCode,
    CyberComponentBinary,
    CyberAbstractionLevel
)
from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports
from saci.modeling.device.component.hardware import HardwareHigh, HardwarePackage, HardwareTechnology
from claripy import BVS

import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================

class ESCHigh(CyberComponentHigh):

    __slots__ = CyberComponentHigh.__slots__ + (
        "is_operational", "fault_detection_flag", "overheat_protection_flag"
    )

    def __init__(self, is_operational=True, fault_detection_flag=False, overheat_protection_flag=False, **kwargs):
        """
        :param is_operational: Indicates if the ESC system is functioning.
        :param fault_detection_flag: Detects any ESC failure conditions.
        :param overheat_protection_flag: Flags overheating conditions.
        """
        super().__init__(**kwargs)
        self.is_operational = is_operational
        self.fault_detection_flag = fault_detection_flag
        self.overheat_protection_flag = overheat_protection_flag  # Detects overheating conditions.

    @property
    def parameter_types(self):
        return {
            "is_operational": bool,
            "fault_detection_flag": bool,
            "overheat_protection_flag": bool,
        }


# =================== Algorithmic Abstraction (Cyber) ===================

class ESCAlgorithmic(CyberComponentAlgorithmic):

    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "efficiency_rating", "response_time", "power_consumption",
        "PWM_signal_anomaly_flag"
    )

    def __init__(
        self, efficiency_rating=0.90, response_time=5, power_consumption=10,
        PWM_signal_anomaly_flag=False, **kwargs
    ):
        """
        :param efficiency_rating: Efficiency in converting input power into motor control.
        :param response_time: ESC response time in milliseconds.
        :param power_consumption: Power consumed by the ESC in watts.
        :param PWM_signal_anomaly_flag: Detects anomalies in PWM signals.
        """
        super().__init__(**kwargs)
        self.efficiency_rating = efficiency_rating
        self.response_time = response_time
        self.power_consumption = power_consumption
        self.PWM_signal_anomaly_flag = PWM_signal_anomaly_flag  # Detects signal spoofing attacks.

        # Symbolic execution variables for ESC control
        self.variables = {
            "input_voltage": BVS("esc_input_voltage", 64),
            "input_current": BVS("esc_input_current", 64),
            "output_voltage": BVS("esc_output_voltage", 64),
            "output_current": BVS("esc_output_current", 64),
            "PWM_frequency": BVS("esc_pwm_frequency", 64),
            "temperature": BVS("esc_temperature", 64),
            "power_efficiency": BVS("esc_power_efficiency", 64),
        }

    @property
    def parameter_types(self):
        return {
            "efficiency_rating": float,
            "response_time": int,
            "power_consumption": float,
            "PWM_signal_anomaly_flag": bool,
        }


# =================== Hardware Abstraction (Physical Layer) ===================

class ESCHardwareHigh(HardwareHigh):

    def __init__(self, **kwargs):
        super().__init__(modality="ESC", **kwargs)


class ESCHardwarePackage(HardwarePackage):

    KNOWN_ESC_CHIPS = [
        "BLHeli_32", "T-Motor F55A", "KISS 32A", "Hobbywing XRotor", "APD 80F3", "Castle Creations Talon"
    ]

    def __init__(self, chip_name, chip_vendor, **kwargs):
        """
        :param chip_name: The name of the ESC chip.
        :param chip_vendor: The manufacturer of the ESC.
        """
        super().__init__(chip_name=chip_name, chip_vendor=chip_vendor, **kwargs)
        if chip_name not in self.KNOWN_ESC_CHIPS:
            _l.warning(f"Unknown ESC chip: {chip_name}. Consider adding it to the known list.")


class ESCHardwareTechnology(HardwareTechnology):

    KNOWN_TECHNOLOGIES = ["Brushed ESC", "Brushless ESC", "Sensorless ESC", "FOC ESC"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of ESC technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown ESC technology: {technology}. Consider adding it to the known list.")


# =================== Full ESC Component Abstraction (Cyber) ===================

class ESC(CyberComponentBase):
    def __init__(self, ports: Optional[Ports]=None, **kwargs):
        super().__init__(
            ports=union_ports({
                "Speed Value": Port(direction=PortDirection.IN),
                "Motor Control": Port(direction=PortDirection.OUT),
            }, ports),
            **kwargs
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ESCHigh(),
            CyberAbstractionLevel.ALGORITHMIC: ESCAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
