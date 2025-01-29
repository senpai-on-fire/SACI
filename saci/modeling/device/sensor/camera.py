from claripy import BVS

from .sensor import SensorHigh, SensorAlgorithmic, Sensor
from saci.modeling.device.component import HardwarePackage, HardwareTechnology, HardwareHigh
from saci.modeling.device.component import CyberAbstractionLevel, CyberComponentSourceCode, CyberComponentBinary
from saci.modeling.communication import BaseCommunication

import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================

class CameraHigh(SensorHigh):

    __slots__ = SensorHigh.__slots__ + ("has_external_input", "powered")

    def __init__(self, powered: bool = True, has_external_input=True, **kwargs):
        """
        :param powered: Whether the camera is powered on.
        :param has_external_input: If the camera can receive external inputs.
        """
        super().__init__(**kwargs)
        self.has_external_input = has_external_input
        self.powered = powered  # Simple state tracking (on/off)


# =================== Algorithmic Abstraction ===================

class CameraAlgorithmic(SensorAlgorithmic):

    __slots__ = SensorAlgorithmic.__slots__ + ("powered", "has_external_input")

    def __init__(self, powered: bool = True, has_external_input=False, **kwargs):
        """
        :param powered: Whether the camera is operational.
        :param has_external_input: If the camera can receive external inputs (e.g., environmental attacks).
        """
        super().__init__(**kwargs)
        self.powered = powered
        self.has_external_input = has_external_input

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

    __slots__ = ("ABSTRACTIONS", "has_external_input", "powered")

    def __init__(
        self,
        has_external_input: bool = False,
        powered: bool = True,
        **kwargs
    ):
        """
        :param has_external_input: Indicates if this sensor can receive external stimuli.
        :param powered: Whether the camera is powered on.
        """
        super().__init__(**kwargs)

        high_abstraction = CameraHigh(powered=powered, has_external_input=has_external_input)
        algo_abstraction = CameraAlgorithmic(powered=powered, has_external_input=has_external_input)

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
        "IMX219", "IMX477", "OV5647", "AR0330", "GC2145",
        "SONY_EXMOR", "MT9V034", "PYTHON500", "Lepton3"
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


######################################################    OLD VERSION    ########################################################################

# from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
# from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
# from ..communication import BaseCommunication


# class CameraHigh(CyberComponentHigh):
#     __slots__ = CyberComponentHigh.__slots__

#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)


# class Camera(CyberComponentBase):
#     __slots__ = ("ABSTRACTIONS", "has_external_input", "powered")

#     def __init__(self, has_external_input=True, powered=True, **kwargs):
#         super().__init__(**kwargs)

#         self.has_external_input = has_external_input
#         self.powered = powered

#         self.ABSTRACTIONS = {
#             CyberAbstractionLevel.HIGH: CameraHigh(),
#             CyberAbstractionLevel.ALGORITHMIC: CyberComponentAlgorithmic(),
#             CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
#             CyberAbstractionLevel.BINARY: CyberComponentBinary(),
#         }

# class LocalizationAlgorithm(CyberComponentAlgorithmic):
#     def __init__(self, enable=False, camera_prioritized=True, **kwargs):
#         super().__init__(**kwargs)
#         self.enable = enable
#         self.camera_prioritized = camera_prioritized
#         self.coordinates = []

#     def navigate(self, communication: BaseCommunication) -> bool:
#         # TODO: model navigation algorithm
#         if not communication.src == "camera":
#             return False
#         if not self.camera_prioritized:
#             return False

#         img = communication.data
#         # TODO: how to model the localization algorithm?
#         self.condition = [0.0, 0.0, 5.0]
        
#         return self.condition