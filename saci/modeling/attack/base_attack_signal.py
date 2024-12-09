
class BaseAttackSignal:
    def __init__(self, src=None, dst=None, modality=None, data=None):
        self.src = src
        self.dst = dst
        self.modality = modality
        self.data = data

