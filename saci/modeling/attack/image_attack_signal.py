from .base_attack_signal import BaseAttackSignal

class ImageAttackSignal(BaseAttackSignal):
    def __init__(self, src=None, dst=None, modality="image", data=None):
        super().__init__(src=src, dst=dst, modality=modality, data=data)
