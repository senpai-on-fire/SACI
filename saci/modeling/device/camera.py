from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from ..communication import BaseCommunication


class CameraHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class Camera(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "has_external_input", "powered")

    def __init__(self, has_external_input=True, powered=True, **kwargs):
        super().__init__(**kwargs)

        self.has_external_input = has_external_input
        self.powered = powered

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: CameraHigh(),
            CyberAbstractionLevel.ALGORITHMIC: CyberComponentAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

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