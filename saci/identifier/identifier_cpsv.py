from typing import List, Optional, Dict, Type, Any

from ..modeling import Device, CPV, ComponentBase, CPSV
from ..modeling.state import GlobalState
from ..modeling.device.component import CyberComponentHigh

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

class Identifier:
    def __init__(self, device: Device, initial_state: GlobalState):
        self.device = device
        self.initial_state = initial_state

    def identify(self, cpsvs : List[CPSV]):
        # For each cpsv, put their description together
        ctrl = Control(unifier=[cpsv.attack_ASP for cpsv in cpsvs] + [self.device.crash_atom])
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
                # extract the attack
                return [y for y in list(optimal_solution.query(cpsv.attack_ASP).all()) for cpsv in cpsvs]
            else:
                return []

    def optimize_crash(self, solutions):
        result = max(solutions, key=lambda s: s.query(self.device.crash_atom).count())
        if result.query(self.device.crash_atom).count() == 0:
            return None
        else:
            return result
