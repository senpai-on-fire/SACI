
from .base_attack_signal import BaseAttackSignal

class EnvironmentalInterference(BaseAttackSignal):
    def __init__(self, src=None, dst=None, modality="airflow", data=None):
        super().__init__(src=src, dst=dst, modality=modality, data=data)
