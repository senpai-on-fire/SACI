from .base_attack_signal import BaseAttackSignal


class SerialAttackSignal(BaseAttackSignal):
    def __init__(self, src=None, dst=None, modality="serial_commands", data=None):
        super().__init__(src=src, dst=dst, modality=modality, data=data)
