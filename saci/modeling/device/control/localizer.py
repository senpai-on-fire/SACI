from saci.modeling.device.component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from typing import List
import claripy
import logging

from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel


_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class LocalizerHigh(CyberComponentHigh):
    __slots__ = (
        "enabled",
        "localization_mode",
        "variables",
    )

    def __init__(self, enabled=False, localization_mode="GPS", **kwargs):
        """
        :param enabled: Boolean flag indicating if localization is enabled.
        :param localization_mode: Primary localization method ("GPS", "Visual", "IMU").
        """
        super().__init__(**kwargs)
        self.enabled = enabled
        self.localization_mode = localization_mode

        # Symbolic variables for localization security and accuracy testing
        self.variables = {
            "localizer_status": claripy.BVS("localizer_status", 8),  # Localization status
            "localization_error": claripy.BVS("localization_error", 32),  # Localization error margin
            "gps_spoofing_flag": claripy.BVS("gps_spoofing_flag", 8),  # GPS spoofing detection
            "imu_drift_error": claripy.BVS("imu_drift_error", 32),  # IMU drift error
        }

    parameter_types = {
        "enabled": bool,
        "localization_mode": str,
    }


# =================== Algorithmic Abstraction (Cyber) ===================


class LocalizerAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "sensor_fusion_enabled",
        "fault_tolerance",
        "variables",
    )

    def __init__(self, sensor_fusion_enabled=True, fault_tolerance=True, **kwargs):
        """
        :param sensor_fusion_enabled: Whether multiple localization sources are fused.
        :param fault_tolerance: Whether the system can handle sensor failures.
        """
        super().__init__(**kwargs)
        self.sensor_fusion_enabled = sensor_fusion_enabled
        self.fault_tolerance = fault_tolerance

        # Symbolic execution variables for localization security and reliability
        self.variables = {
            "localization_confidence": claripy.BVS("localization_confidence", 32),  # Confidence level in localization
            "gps_latency": claripy.BVS("gps_latency", 32),  # GPS delay in milliseconds
            "vision_error": claripy.BVS("vision_error", 32),  # Visual localization error
            "fault_detection_flag": claripy.BVS("fault_detection_flag", 8),  # Sensor fault detection flag
        }

    def position(self, localization_components: List[CyberComponentBase]) -> bool:
        """
        Determines if the CPS's position can be accurately estimated.
        """
        if not localization_components:
            return False

        # Check if at least one component provides valid localization data
        # TODO: fix once we have a new abstractions mechanism
        return True

    parameter_types = {
        "sensor_fusion_enabled": bool,
        "fault_tolerance": bool,
    }


# =================== Full CPS Localizer Model Abstraction (Cyber) ===================


class Localizer(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "enabled", "localization_mode", "sensor_fusion_enabled", "fault_tolerance")

    def __init__(
        self, enabled=False, localization_mode="GPS", sensor_fusion_enabled=True, fault_tolerance=True, **kwargs
    ):
        """
        :param enabled: Boolean flag indicating if localization is enabled.
        :param localization_mode: Primary localization method ("GPS", "Visual", "IMU").
        :param sensor_fusion_enabled: Whether multiple localization sources are fused.
        :param fault_tolerance: Whether the system can handle sensor failures.
        """
        super().__init__(**kwargs)

        self.enabled = enabled
        self.localization_mode = localization_mode
        self.sensor_fusion_enabled = sensor_fusion_enabled
        self.fault_tolerance = fault_tolerance

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: LocalizerHigh(enabled=enabled, localization_mode=localization_mode),
            CyberAbstractionLevel.ALGORITHMIC: LocalizerAlgorithmic(
                sensor_fusion_enabled=sensor_fusion_enabled, fault_tolerance=fault_tolerance
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "enabled": bool,
        "localization_mode": str,
        "sensor_fusion_enabled": bool,
        "fault_tolerance": bool,
    }
