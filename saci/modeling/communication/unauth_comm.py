from .base_comm import BaseCommunication


class UnauthenticatedCommunication(BaseCommunication):
    def __init__(self, src=None, dst=None, identifier=None, seq=0, data=None):
        super().__init__(src=src, dst=dst, data=data)
        self.identifier = identifier
        self.seq = seq
