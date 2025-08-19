from .base_attack_signal import BaseAttackSignal


class AcousticAttackSignal(BaseAttackSignal):
    def __init__(self, src=None, dst=None, modality="audio", data=None):
        super().__init__(src=src, dst=dst, data=modality)
