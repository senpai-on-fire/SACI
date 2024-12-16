import re
from io import StringIO
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

    def write_asp(self, f):
        """Aid conversion of CPV definitions to ASP.

        This is not meant to be left in here for programmatic use. If
        we wanted to do that we would use Clingo directly.
        """

        ident = _camel_to_snake_case(type(self).__name__[:-3])

        print(f"cpv({ident}).", file=f)
        for req in self.required_components:
            print(f"cpv({ident}, required_component, {_comp_type_to_asp(req)}).", file=f)
        if self.entry_component:
            print(f"cpv({ident}, entry_component, {_comp_type_to_asp(self.entry_component)}).", file=f)
        if self.exit_component:
            print(f"cpv({ident}, exit_component, {_comp_type_to_asp(self.exit_component)}).", file=f)
        # what is a goal?
        for goal in self.goals:
            print(f"cpv({ident}, goal_component, {_comp_type_to_asp(goal)}).", file=f)
        for vuln in self.vulnerabilities:
            print(f"cpv({ident}, vulnerability, {_vuln_type_to_asp(vuln)}).", file=f)
        for thing, condition in self.initial_conditions.items():
            print(f"cpv({ident}, initial_condition({_asp_string(thing)}), {_asp_string(condition)}).", file=f)
        for requirement in self.attack_requirements:
            print(f"cpv({ident}, attack_requirement, {_asp_string(requirement)}).", file=f)
        for i, vector in enumerate(self.attack_vectors):
            # TODO: generate this ID better?
            vector_id = f"vector_{ident}_{i}"
            print(f"attack_vector({vector_id}).", file=f)
            print(f"attack_vector({vector_id}, name, {_asp_string(vector.name)}).", file=f)
            signal_id = f"signal_{ident}_{i}"
            print(f"attack_signal({signal_id}).", file=f)
            # TODO: tie these src/dst to the required_components?
            print(f"attack_signal({signal_id}, src, {_comp_type_to_asp(vector.signal.src)}).", file=f)
            print(f"attack_signal({signal_id}, dst, {_comp_type_to_asp(vector.signal.dst)}).", file=f)
            print(f"attack_signal({signal_id}, modality, {_asp_string(vector.signal.modality)}).", file=f)
            if vector.signal.data is not None:
                print(f"attack_signal({signal_id}, data, {_asp_string(vector.signal.data)}).", file=f)
            print(f"attack_vector({vector_id}, signal, {signal_id}).", file=f)
            print(f"attack_vector({vector_id}, required_access_level, {_asp_string(vector.required_access_level)}).", file=f)
            for conf_key, conf_value in vector.configuration.items():
                print(f"attack_vector({vector_id}, configuration({_asp_string(conf_key)}), {_asp_string(conf_value)}).", file=f)
            print(f"attack_vector({vector_id}, name, {_asp_string(vector.name)}).", file=f)
            print(f"cpv({ident}, attack_vector, {vector_id}).", file=f)
        for i, impact in enumerate(self.attack_impacts):
            # TODO: generate this ID better?
            impact_id = f"impact_{ident}_{i}"
            print(f"attack_impact({impact_id}).", file=f)
            print(f"attack_impact({impact_id}, category, {_asp_string(impact.category)}).", file=f)
            print(f"attack_impact({impact_id}, description, {_asp_string(impact.description)}).", file=f)
            print(f"cpv({ident}, attack_vector, {impact_id}).", file=f)
        for i, step in enumerate(self.exploit_steps):
            print(f"cpv({ident}, exploit_step({i}), {_asp_string(step)}).", file=f)
        for url in self.associated_files:
            print(f"cpv({ident}, associated_file, {_asp_string(url)}.", file=f)
        for url in self.reference_urls:
            print(f"cpv({ident}, reference_url, {_asp_string(url)}).", file=f)

    def to_asp(self):
        f = StringIO()
        self.write_asp(f)
        return f.getvalue()
