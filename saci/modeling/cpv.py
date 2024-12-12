import re
from typing import List, Any, Optional, Dict, Type, TextIO

from .device import Device, CyberComponentBase
from .state import GlobalState
from .vulnerability import BaseVulnerability
from .attack.base_attack_vector import BaseAttackVector
from .attack.base_attack_impact import BaseAttackImpact

_camel_re = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
def _camel_to_snake_case(name):
    return _camel_re.sub('_', name).lower()

def _comp_type_to_asp(comp):
    # TODO: remove High/Algorithmic/etc if it's there
    return _camel_to_snake_case(type(comp).__name__)

def _vuln_type_to_asp(comp):
    return _camel_to_snake_case(type(comp).__name__)

def _asp_escape_char(c):
    match c:
        case '\\':
            return '\\\\'
        case '\n':
            return '\\n'
        case '"':
            return '\\"'
        case _:
            return c

def _asp_string(s):
    return '"' + ''.join(_asp_escape_char(c) for c in s) + '"'


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
        self.initial_conditions = initial_conditions or {}
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

    def is_possible_path(self, path: List[CyberComponentBase]):
        
        if len(path) == len(self.required_components):

            for i in range(len(path)):
                if type(path[i]) is type(self.required_components[i]):
                    continue
                else:
                    return False
        else: 
            return False
        
        return True

    def __repr__(self):
        return f"<{self.__class__.__name__}>"

    def to_asp(self):
        """Aid conversion of CPV definitions to ASP.

        This is not meant to be left in here for programmatic use. If
        we wanted to do that we would use Clingo directly.
        """

        ident = _camel_to_snake_case(type(self).__name__[:-3])

        out = ""
        out += f"cpv({ident}).\n"
        for req in self.required_components:
            out += f"cpv({ident}, required_component, {_comp_type_to_asp(req)}).\n"
        if self.entry_component:
            out += f"cpv({ident}, entry_component, {_comp_type_to_asp(self.entry_component)}).\n"
        if self.exit_component:
            out += f"cpv({ident}, exit_component, {_comp_type_to_asp(self.exit_component)}).\n"
        # what is a goal?
        for goal in self.goals:
            out += f"cpv({ident}, goal_component, {_comp_type_to_asp(goal)}).\n"
        for vuln in self.vulnerabilities:
            out += f"cpv({ident}, vulnerability, {_vuln_type_to_asp(vuln)}).\n"
        for thing, condition in self.initial_conditions.items():
            out += f"cpv({ident}, initial_condition({_asp_string(thing)}), {_asp_string(condition)}).\n"
        for requirement in self.attack_requirements:
            out += f"cpv({ident}, attack_requirement, {_asp_string(requirement)}).\n"
        for vector in self.attack_vectors:
            # TODO: actually flesh this out
            out += f"cpv({ident}, attack_vector, {_asp_string(repr(vector))}).\n"
        for impact in self.attack_impacts:
            # TODO: actually flesh this out
            out += f"cpv({ident}, attack_vector, {_asp_string(repr(impact))}).\n"
        for i, step in enumerate(self.exploit_steps):
            out += f"cpv({ident}, exploit_step({i}), {_asp_string(step)}).\n"
        for url in self.associated_files:
            out += f"cpv({ident}, associated_file, {_asp_string(url)}.\n"
        for url in self.reference_urls:
            out += f"cpv({ident}, reference_url, {_asp_string(url)}).\n"

        return out
