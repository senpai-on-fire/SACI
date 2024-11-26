from typing import List, Optional, Dict, Type, TextIO

from .device import Device, CyberComponentBase
from .state import GlobalState
from .vulnerability import BaseVulnerability


class CPV:
    """
    A Cyber-Physical BaseVulnerability (CPV) is a representation of a vulnerability in a cyber-physical system.
    A CPV consists of a set of goal states, an entry state, and an attack. The attack is a directed graph that

    Name CPVs based on the entry component and the physical impact.
    """

    NAME: str = "Unspecified"
    DESCRIPTION: str = "Unspecified"

    def __init__(
        self,
        required_components: Optional[List[CyberComponentBase]] = None,
        entry_component: CyberComponentBase = None,
        exit_component: CyberComponentBase = None,
        goals: List[CyberComponentBase] = None,
        vulnerabilities: List[BaseVulnerability] = None,
        initial_conditions: list[str] = None,
        final_conditions: list[str] = None,
        steps: list[str] = None,
        associated_files: list[str] = None,
        reference_urls: list[str] = None,
    ):
        self.required_components = required_components or []
        self.entry_component = entry_component
        self.exit_component = exit_component
        self.goals = goals or []
        self.vulnerabilities = vulnerabilities or []
        self.initial_conditions = initial_conditions or []
        self.final_conditions = final_conditions or []
        self.steps = steps or []
        self.associated_files = associated_files or []
        self.reference_urls = reference_urls or []

    def vulnerable(self, device: Device):
        for vulnerability in self.vulnerabilities:
            if not vulnerability.exists(device):
                return False

        return True

    def in_goal_state(self, state: GlobalState):
        return False

    def is_possible_path(self, path: List[CyberComponentBase]):
        raise NotImplementedError()

    def __repr__(self):
        return f"<{self.__class__.__name__}>"
