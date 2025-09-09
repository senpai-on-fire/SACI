from .base_attack_signal import BaseAttackSignal


class MagneticAttackSignal(BaseAttackSignal):
    def __init__(self, src=None, dst=None, modality="magnetic", data=None):
        super().__init__(src=src, dst=dst, modality=modality, data=data)
