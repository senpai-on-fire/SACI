
class ExternalInput:
    """
    Used to describe input that is coming from either an Attacker, or some external source that is not modeled in
    SACI as a normal device
    """
    def __init__(self, data=None):
        self.data = data
