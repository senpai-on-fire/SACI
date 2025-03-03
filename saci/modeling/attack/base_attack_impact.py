
class BaseAttackImpact:
    """Attack impact for CPS"""
    def __init__(self, category=None, description=None):
        self.category = category
        self.description = description


class BaseCompEffect:
    """Attack impact for component"""
    def __init__(self, category=None, description=None):
        self.category = category
        self.description = description