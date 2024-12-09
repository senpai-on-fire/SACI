from typing import List, Optional, Dict, Type, Any, Tuple

from saci.modeling import Device, CPV, ComponentBase, CPSV
from saci.modeling.state import GlobalState
from saci.modeling.device.component import CyberComponentHigh
from saci.modeling.behavior import Behaviors
from saci.modeling.cpvpath import CPVPath

from clorm import FactBase
from clorm.clingo import Control

import logging
l = logging.getLogger(__name__)

# # TODO: This should go in another package or something
# # Solver data model
# class StateVariable(Predicate):
#     time: int
#     name: ConstantStr
#     value: SimpleField

# class Component(Predicate):
#     name: str

# class ComponentEdge(Predicate):
#     src: Component
#     dst: Component

# class ComponentPath(Predicate):
#     time: int
#     src: Component
#     dst: Component

# class GoalFound(Predicate):
#     time: int


def create_CPV_class(name, **attributes):
    # Create a new class with the given name, base classes, and attributes
    return type(name, CPV, attributes)

class IdentifierCPSV:
    def __init__(self, device: Device, initial_state: GlobalState):
        self.device = device
        self.initial_state = initial_state

    def identify(self, cpsvs : List[CPSV]) -> List[Tuple[CPV, CPVPath]]:
        # For each cpsv, put their description together
        ctrl = Control(unifier=[self.device.crash_atom] + [x.attack_ASP for x in cpsvs])
        for cpsv in cpsvs:
            if hasattr(cpsv, 'rulefile') and cpsv.rulefile:
                l.info(f'loading {cpsv.rulefile}')
                ctrl.load(cpsv.rulefile)
        
        # TODO: the description should be those that are on the same level of the CPSVs and relavent to the CPSVs only
        ctrl.load(self.device.description)

        ctrl.ground([("base", [])])
        
        with ctrl.solve(yield_=True) as handle:
            solutions = [FactBase(model.facts(atoms=True)) for model in handle]
            # Find the solutions that makes the CPS crash earliest.
            optimal_solution = self.optimize_crash(solutions)
            if optimal_solution is not None:
                path = []
                inputs = []
                for cpsv in cpsvs:
                    if optimal_solution.query(cpsv.attack_ASP).count() > 0:
                        path.append(cpsv.component)
                        time = optimal_solution.query(cpsv.attack_ASP).first().time
                        inputs.append({cpsv.component.name: f'{cpsv.input} at Time {time}'})
                # extract the attack
                newCPV = CPV()
                newCPV.NAME = 'NEWCPV'
                behaviors = Behaviors(None)
                cpvpath = CPVPath(path, behaviors)
                cpvpath.cpv_inputs = inputs 
                # TODO: in theory, a new CPV can return multiple possible paths. Here we only take the optimal one.
                return [(newCPV, [cpvpath])]
            else:
                return []

    def optimize_crash(self, solutions):
        result = max(solutions, key=lambda s: s.query(self.device.crash_atom).count())
        if result.query(self.device.crash_atom).count() == 0:
            return None
        else:
            return result
