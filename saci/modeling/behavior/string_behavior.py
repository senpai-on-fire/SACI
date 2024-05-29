from .behavior import BehaviorBase


class StringBehavior(BehaviorBase):
    def __init__(self, desc):
        super().__init__()
        self.desc = desc

    def __repr__(self):
        return self.desc
