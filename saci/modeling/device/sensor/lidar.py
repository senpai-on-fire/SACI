import logging

import claripy

from saci.modeling.device.component import (
    CyberAbstractionLevel,
    CyberComponentBinary,
    CyberComponentSourceCode,
    HardwarePackage,
    HardwareTechnology,
)

# Adjust these imports based on your project structure
from .sensor import Sensor, SensorAlgorithmic, SensorHigh

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================


class LidarSensorHigh(SensorHigh):
    __slots__ = SensorHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # High-level operational flags / aggregated states
        self.variables["is_calibrated"] = claripy.BVS("lidar_calibrated", 1)
        self.variables["obstacle_detected"] = claripy.BVS("lidar_obstacle", 1)
        self.variables["health_ok"] = claripy.BVS("lidar_health_ok", 1)


# =================== Algorithmic Abstraction ===================


class LidarSensorAlgorithmic(SensorAlgorithmic):
    __slots__ = SensorAlgorithmic.__slots__ + (
        "has_intensity",
        "enabled",
        "max_range_m",
        "fov_deg",
        "scan_rate_hz",
    )

    def __init__(
        self,
        has_intensity=True,
        enabled=True,
        max_range_m=100.0,
        fov_deg=360.0,
        scan_rate_hz=10.0,
        **kwargs,
    ):
        """
        :param has_intensity: Whether the LiDAR reports per-return intensity.
        :param enabled: Whether the LiDAR is enabled.
        :param max_range_m: Max measurable range (meters).
        :param fov_deg: Horizontal field of view (degrees).
        :param scan_rate_hz: Scans per second.
        """
        super().__init__(**kwargs)

        self.has_intensity = has_intensity
        self.enabled = enabled
        self.max_range_m = max_range_m
        self.fov_deg = fov_deg
        self.scan_rate_hz = scan_rate_hz

        # Symbolic variables to represent LiDAR outputs
        # Example sizes (bit-widths) are illustrative; tune as needed.
        self.variables["range_array"] = claripy.BVS("lidar_range_array", 32 * 1024)
        self.variables["intensity_array"] = claripy.BVS("lidar_intensity_array", 16 * 1024)
        self.variables["num_points"] = claripy.BVS("lidar_num_points", 16)
        self.variables["noise"] = claripy.BVS("lidar_noise", 32)
        self.variables["pose_delta"] = claripy.BVS("lidar_pose_delta", 64)  # small ego-motion proxy


# =================== Full Sensor Abstraction ===================


class Lidar(Sensor):
    __slots__ = ("has_intensity", "enabled", "ABSTRACTIONS")

    def __init__(self, has_intensity=True, enabled=True, **kwargs):
        super().__init__(**kwargs)

        high_abstraction = LidarSensorHigh()
        algo_abstraction = LidarSensorAlgorithmic(
            has_intensity=has_intensity, enabled=enabled
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== Hardware Abstractions ===================


class LidarSensorHardware(Sensor):
    __slots__ = Sensor.__slots__

    def __init__(
        self,
        comm_interface="UART",  # e.g., UART | CAN | Ethernet | USB
        baudrate=115200,
        can_bitrate=500_000,
        ip_address="192.168.1.10",
        range_meters=100,
        fov_deg=360,
        scan_rate_hz=10,
        **kwargs,
    ):
        """
        :param comm_interface: Physical communication interface used by the LiDAR.
        :param baudrate: UART baudrate (if UART).
        :param can_bitrate: CAN bitrate (if CAN).
        :param ip_address: Device IP (if Ethernet).
        :param range_meters: Max range in meters (nominal).
        :param fov_deg: Field of view in degrees (nominal).
        :param scan_rate_hz: Scans per second (nominal).
        """
        super().__init__(**kwargs)
        self.variables = {}  # Initialize variables dictionary

        self.comm_interface = comm_interface
        self.baudrate = baudrate
        self.can_bitrate = can_bitrate
        self.ip_address = ip_address

        self.range_meters = range_meters
        self.fov_deg = fov_deg
        self.scan_rate_hz = scan_rate_hz

        # Simulated hardware registers / states
        self.variables["hardware_status"] = claripy.BVS("lidar_hw_status", 8)
        self.variables["hardware_config"] = claripy.BVS("lidar_hw_config", 16)
        self.variables["temperature"] = claripy.BVS("lidar_temp_c", 16)
        self.variables["supply_voltage"] = claripy.BVS("lidar_vin_mv", 16)


class LidarSensorHWPackage(HardwarePackage):
    KNOWN_CHIP_NAMES = [
        "Velodyne VLP-16",
        "Velodyne HDL-32E",
        "Ouster OS1-64",
        "Hokuyo UTM-30LX",
        "RPLIDAR A3",
        "Livox Mid-40",
        "Quanergy M8",
    ]

    def __init__(self, sensor_name, sensor_vendor, **kwargs):
        """
        :param sensor_name: The name/model of the LiDAR unit.
        :param sensor_vendor: The manufacturer/vendor.
        """
        super().__init__(chip_name=sensor_name, chip_vendor=sensor_vendor, **kwargs)
        if sensor_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(
                f"Unknown LiDAR chip name: {sensor_name}. "
                f"Please add it to LidarSensorHWPackage.KNOWN_CHIP_NAMES."
            )


class LidarSensorHWTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = [
        "Rotating ToF",
        "Solid-State MEMS",
        "Flash LiDAR",
        "FMCW LiDAR",
    ]

    def __init__(self, technology, **kwargs):
        """
        :param technology: LiDAR technology type.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(
                f"Unknown LiDAR technology: {technology}. "
                f"Please add it to LidarSensorHWTechnology.KNOWN_TECHNOLOGIES."
            )
