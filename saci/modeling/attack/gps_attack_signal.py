from .base_attack_signal import BaseAttackSignal

class GPSAttackSignal(BaseAttackSignal):
    def __init__(self, src=None, dst=None, modality="gps"):
        super().__init__(src=src, dst=dst, modality=modality)
        pass