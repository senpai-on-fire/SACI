from typing import List, Optional, Dict, Type

from .device import Device, ComponentBase
from .state import GlobalState
from .vulnerability import Vulnerability


class CPV:
    """
    A Cyber-Physical BaseVulnerability (CPV) is a representation of a vulnerability in a cyber-physical system.
    A CPV consists of a set of goal states, an entry state, and an attack. The attack is a directed graph that

    """
    def __init__(
        self,
        required_components: Optional[List[Type[ComponentBase]]] = None,
        entry_component: ComponentBase = None,
        goals: List[ComponentBase] = None,
        vulnerabilities: List[Vulnerability] = None
    ):
        self.required_components = required_components or []
        self.entry_component = entry_component
        self.vulnerabilities = vulnerabilities or []

    def vulnerable(self, device: Device):
        for vulnerability in self.vulnerabilities:
            if not vulnerability.exists(device):
                return False

        return True

    def in_goal_state(self, state: GlobalState):
        return False

