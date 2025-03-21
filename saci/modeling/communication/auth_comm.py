from .base_comm import BaseCommunication


class AuthenticatedCommunication(BaseCommunication):
    def __init__(self, identifier=None, seq=0, **kwargs):
        super().__init__(**kwargs)
        self.identifier = identifier
        self.seq = seq
