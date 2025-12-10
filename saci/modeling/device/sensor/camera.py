import logging

from claripy import BVS

from saci.modeling.device.component import (
    CyberAbstractionLevel,
    CyberComponentBinary,
    CyberComponentSourceCode,
    HardwareHigh,
    HardwarePackage,
    HardwareTechnology,
)

from .sensor import Sensor, SensorAlgorithmic, SensorHigh

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================


class CameraHigh(SensorHigh):
    __slots__ = SensorHigh.__slots__ + ("powered",)

    def __init__(self, powered: bool = True, **kwargs):
        """
        :param powered: Whether the camera is powered on.
        """
        super().__init__(**kwargs)
        self.powered = powered  # Simple state tracking (on/off)


# =================== Algorithmic Abstraction ===================


class CameraAlgorithmic(SensorAlgorithmic):
    __slots__ = SensorAlgorithmic.__slots__ + ("powered",)

    def __init__(self, powered: bool = True, **kwargs):
        """
        :param powered: Whether the camera is operational.
        """
        super().__init__(**kwargs)
        self.powered = powered

        # Symbolic variables for detailed camera properties
        self.variables["frame_rate"] = BVS("camera_frame_rate", 32)
        self.variables["resolution_width"] = BVS("camera_width", 32)
        self.variables["resolution_height"] = BVS("camera_height", 32)
        self.variables["color_depth"] = BVS("camera_color_depth", 16)
        self.variables["focus_distance"] = BVS("camera_focus_distance", 32)  # Optional

    def can_capture_frame(self) -> bool:
        """
        Determines if the camera can capture a frame.
        """
        return self.powered  # Camera must be powered to function


# =================== Full Sensor Abstraction ===================


class Camera(Sensor):
    __slots__ = ("ABSTRACTIONS", "powered")

    def __init__(self, powered: bool = True, **kwargs):
        """
        :param powered: Whether the camera is powered on.
        """
        super().__init__(**kwargs)

        high_abstraction = CameraHigh(powered=powered)
        algo_abstraction = CameraAlgorithmic(powered=powered)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: high_abstraction,
            CyberAbstractionLevel.ALGORITHMIC: algo_abstraction,
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


# =================== Hardware Abstractions ===================


class CameraHWHigh(HardwareHigh):
    def __init__(self, **kwargs):
        super().__init__(modality="camera", **kwargs)


class CameraHWPackage(HardwarePackage):
    KNOWN_CHIP_NAMES = [
        "IMX219",
        "IMX477",
        "OV5647",
        "AR0330",
        "GC2145",
        "SONY_EXMOR",
        "MT9V034",
        "PYTHON500",
        "Lepton3",
    ]

    def __init__(self, camera_name, camera_vendor, **kwargs):
        """
        :param camera_name: The name of the camera chip.
        :param camera_vendor: The manufacturer of the camera chip.
        """
        super().__init__(chip_name=camera_name, chip_vendor=camera_vendor, **kwargs)
        if camera_name not in self.KNOWN_CHIP_NAMES:
            _l.warning(f"Unknown camera chip name: {camera_name}. Please add it to CameraHWPackage.")


class CameraHWTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = ["CMOS", "CCD", "Infrared", "Thermal", "LiDAR"]

    def __init__(self, technology, **kwargs):
        """
        :param technology: Type of camera technology used.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(f"Unknown camera technology: {technology}. Please add it to CameraHWTechnology.")
