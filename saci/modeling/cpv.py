from typing import List, Any, Optional, Dict, Type, TextIO

from .device import Device, CyberComponentBase
from .state import GlobalState
from .vulnerability import BaseVulnerability
from .attack.base_attack_vector import BaseAttackVector
from .attack.base_attack_impact import BaseAttackImpact


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
        required_components: List[CyberComponentBase] = None,
        entry_component: CyberComponentBase = None,
        exit_component: CyberComponentBase = None,
        goals: List[CyberComponentBase] = None,
        vulnerabilities: List[BaseVulnerability] = None,
        initial_conditions: dict[str, Any] = None,
        # final_conditions: list[str] = None,
        attack_vectors: List[BaseAttackVector] = None,  
        attack_requirements: list[str] = None, 
        exploit_steps: list[str] = None,
        attack_impacts: List[BaseAttackImpact] = None,
        associated_files: list[str] = None,
        reference_urls: list[str] = None,
    ):
        self.required_components = required_components or []
        self.entry_component = entry_component
        self.exit_component = exit_component
        self.goals = goals or []
        self.vulnerabilities = vulnerabilities or []
        self.initial_conditions = initial_conditions or []
        # self.final_conditions = final_conditions or []
        self.attack_vectors = attack_vectors or []
        self.attack_requirements = attack_requirements or []
        self.exploit_steps = exploit_steps or []
        self.attack_impacts = attack_impacts or []
        self.associated_files = associated_files or []
        self.reference_urls = reference_urls or []

    def vulnerable(self, device: Device):
        for vulnerability in self.vulnerabilities:
            if not vulnerability.exists(device):
                return False

        return True

    def in_goal_state(self, state: GlobalState):
        return False

    # def is_possible_path(self, path: List[Type[CyberComponentBase]]):
    #     for required in self.required_components:
    #         # Check if the exact class exists in path
    #         if not any(p is required for p in path):
    #             return False
    #     return True

    def is_possible_path(self, path: List[CyberComponentBase]):
        
        if len(path) == len(self.required_components):

            for i in range(len(path)):
                if type(path[i]) is type(self.required_components[i]):
                    continue
                else:
                    #print(f"Components {self.required_components[i]} and {path[i]} not satisfied by path")
                    return False
        else: 
            return False
        
        return True

    def __repr__(self):
        return f"<{self.__class__.__name__}>"
