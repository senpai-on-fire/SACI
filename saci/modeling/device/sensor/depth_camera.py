import logging

from claripy import BVS

from saci.modeling.device.component import (
    CyberAbstractionLevel,
    CyberComponentBinary,
    CyberComponentSourceCode,
    HardwarePackage,
    HardwareTechnology,
)

from .sensor import Sensor, SensorAlgorithmic, SensorHigh

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================


class DepthCameraHigh(SensorHigh):
    __slots__ = SensorHigh.__slots__ + ("supports_stereo_vision", "enabled")

    def __init__(self, supports_stereo_vision=True, enabled=True, **kwargs):
        """
        :param supports_stereo_vision: Whether the camera supports stereo vision.
        :param enabled: Whether the depth camera is enabled.
        """
        super().__init__(**kwargs)
        self.supports_stereo_vision = supports_stereo_vision
        self.enabled = enabled


# =================== Algorithmic Abstraction ===================


class DepthCameraAlgorithmic(SensorAlgorithmic):
    __slots__ = SensorAlgorithmic.__slots__ + ("supports_stereo_vision", "enabled")

    def __init__(self, supports_stereo_vision=True, enabled=True, **kwargs):
        """
        :param supports_stereo_vision: Whether the camera supports stereo vision.
        :param enabled: Whether the depth camera is enabled.
        """
        super().__init__(**kwargs)

        # Symbolic variables for depth camera modeling
        self.variables["frame_rate"] = BVS("depth_cam_frame_rate", 32)
        self.variables["resolution_width"] = BVS("depth_cam_width", 32)
        self.variables["resolution_height"] = BVS("depth_cam_height", 32)
        self.variables["max_depth_range"] = BVS("depth_cam_max_depth", 32)
        self.variables["depth_precision"] = BVS("depth_cam_precision", 32)

        if supports_stereo_vision:
            self.variables["stereo_offset"] = BVS("depth_cam_stereo_offset", 32)  # Extra variable for stereo vision

        self.enabled = enabled

    def can_capture_depth_map(self) -> bool:
        """
        Determines if the depth camera can capture a depth map.
        """
        return self.enabled


# =================== Full Sensor Abstraction ===================


class DepthCamera(Sensor):
    __slots__ = ("supports_stereo_vision", "enabled", "ABSTRACTIONS")

    def __init__(self, supports_stereo_vision: bool = True, enabled: bool = True, **kwargs):
        super().__init__(**kwargs)

        high_abstraction = DepthCameraHigh(supports_stereo_vision=supports_stereo_vision, enabled=enabled)
        algo_abstraction = DepthCameraAlgorithmic(supports_stereo_vision=supports_stereo_vision, enabled=enabled)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== Hardware Abstractions ===================


class DepthCameraHardware(Sensor):
    __slots__ = Sensor.__slots__

    def __init__(self, usb_interface="USB3.0", i2c_address=None, **kwargs):
        """
        :param usb_interface: USB interface type (e.g., USB2.0, USB3.0).
        :param i2c_address: I2C address if the camera supports I2C communication.
        """
        super().__init__(**kwargs)
        self.usb_interface = usb_interface
        self.i2c_address = i2c_address
        self.variables = {}  # Initialize variables dictionary

        # Simulated hardware register values
        self.variables["hardware_status"] = BVS("depth_cam_hw_status", 8)  # 8-bit status register
        self.variables["hardware_config"] = BVS("depth_cam_hw_config", 16)  # 16-bit config register


class DepthCameraHWPackage(HardwarePackage):
    KNOWN_CHIP_NAMES = [
        "Intel_Realsense_D435",
        "Intel_Realsense_L515",
        "Orbbec_Astra",
        "Azure_Kinect",
        "ZED2",
        "ZED_Mini",
    ]

    def __init__(self, camera_name, camera_vendor, **kwargs):
        """
        :param camera_name: The name of the depth camera chip.
        :param camera_vendor: The manufacturer of the depth camera chip.
        """
        super().__init__(chip_name=camera_name, chip_vendor=camera_vendor, **kwargs)
        if camera_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(f"Unknown depth camera chip name: {camera_name}. Please add it to DepthCameraHWPackage.")


class DepthCameraHWTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["Structured Light", "Time of Flight (ToF)", "Stereo Vision", "Lidar-based"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of depth camera technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown depth camera technology: {technology}. Please add it to DepthCameraHWTechnology.")
