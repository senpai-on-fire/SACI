from .base_attack_signal import BaseAttackSignal


class PacketAttackSignal(BaseAttackSignal):
    def __init__(self, src=None, dst=None, modality="network_packets", data=None):
        super().__init__(src=src, dst=dst, modality=modality, data=data)
