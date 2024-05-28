from typing import List, Optional, Dict, Type

from .device import Device, CyberComponentBase
from .state import GlobalState
from .vulnerability import BaseVulnerability


class CPV:
    """
    A Cyber-Physical BaseVulnerability (CPV) is a representation of a vulnerability in a cyber-physical system.
    A CPV consists of a set of goal states, an entry state, and an attack. The attack is a directed graph that

    """

    NAME: str = "Unspecified"

    def __init__(
        self,
        required_components: Optional[List[Type[CyberComponentBase]]] = None,
        entry_component: CyberComponentBase = None,
        exit_component: CyberComponentBase = None,
        goals: List[CyberComponentBase] = None,
        vulnerabilities: List[BaseVulnerability] = None
    ):
        self.required_components = required_components or []
        self.entry_component = entry_component
        self.exit_component = exit_component
        self.goals = goals or []
        self.vulnerabilities = vulnerabilities or []

    def vulnerable(self, device: Device):
        for vulnerability in self.vulnerabilities:
            if not vulnerability.exists(device):
                return False

        return True

    def in_goal_state(self, state: GlobalState):
        return False

