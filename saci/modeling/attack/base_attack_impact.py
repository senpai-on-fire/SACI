from typing import List, Union


class BaseAttackImpact:
    """Attack impact for CPS"""
    def __init__(self, category=None, description=None):
        self.category = category
        self.description = description


class BaseCompEffect:
    """Attack impact for component
    
    Args:
        category (str): Category of the attack impact.
            - Integrity: The assurance that sensor data is accurate and unaltered
            - Availability: 
            - Confidentiality:
        description (str): Description of the attack impact.
    """
    def __init__(self, category: Union[str, List] = None, description=None):
        self.category = category
        self.description = description