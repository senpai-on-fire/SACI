from .component import ComponentHigh, ComponentAlgorithmic
from ..communication import BaseCommunication


class CameraHigh(ComponentHigh):
    __slots__ = ComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


# class LocalizationAlgorithm(ComponentAlgorithmic):
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