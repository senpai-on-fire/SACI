
class BaseCommunication:
    def __init__(self, src=None, dst=None, data=None, signal_strength=None):
        self.src = src
        self.dst = dst
        self.data = data
        self.signal_strength = signal_strength

