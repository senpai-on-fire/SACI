from typing import Tuple, Optional, List

from ..constrainers import get_constrainer, get_constrainer_and_abstract_component
from ..modeling import CPV
from ..modeling.device import ComponentBase
from ..modeling.state import GlobalState
from ..modeling.behavior import Behaviors
from ..identifier import IdentifierCPV, IdentifierCPSV

from saci_db.devices.px4_quadcopter_device import PX4Quadcopter
from saci_db.cpvs import MavlinkCPV
from saci_db.vulns import MavlinkCPSV, SiKCPSV

import logging
l = logging.getLogger(__name__)
# l.setLevel('DEBUG')


class CPVPath:
    def __init__(self, path, behaviors):
        self.path: List[ComponentBase] = path
        self.final_behaviors: Behaviors = behaviors

    def __repr__(self):
        return f"<CPVPath: {repr(self.path)} -> {repr(self.final_behaviors)}>"


def identify(cps, initial_state, cpv_model: Optional[CPV] = None) -> Tuple[CPV, List[CPVPath]]:
    """
    Identify if the given CPV model may exist in the CPS model.
    Return a CPV description if it exists, otherwise return None.
    """
    identifier = IdentifierCPV(cps, initial_state)
    to_return = []
    for path in identifier.identify(cpv_model):
        to_return.append(CPVPath(path, Behaviors([])))
    return cpv_model, to_return
    # TODO: currently I'm hacking it to do CPS-V matching
    # return identify_from_cpsv(cps, cpv_model.vulnerabilities, initial_state)

def identify_from_cpsv(cps, cpsvs, initial_state):
    """
    Return: a list of (CPVModel, CPVdescription, input)
    """
    # TODO: create a CPVModel and CPVdescription based on inputs and CPSV
    identifier = IdentifierCPSV(cps, initial_state)
    return [(None, None, x) for x in identifier.identify(cpsvs)]


def constrain_cpv_path(cps, cpv_model, cpv_path) -> Optional:
    """
    Constrain a CPV path on a CPV model with the goal of generating
    """
    behaviors = cpv_path.final_behaviors
    state = None  # TODO:
    constraints = set()  # TODO:

    inputs = [ ]
    for component in cpv_path.path:
        if hasattr(component, "ABSTRACTIONS"):
            # this is a combo component
            constrainercls_and_abstractions = list(get_constrainer_and_abstract_component(component))
            if not constrainercls_and_abstractions:
                raise TypeError(f"No constrainer found for {component}")

        else:
            # this is an abstracted component
            constrainer_clses = list(get_constrainer(component))
            if not constrainer_clses:
                raise TypeError(f"No constrainer found for {component}")

            constrainercls_and_abstractions = [(cls, component) for cls in constrainer_clses]

        for constrainer_cls, abstraction in constrainercls_and_abstractions:
            constrainer = constrainer_cls()

            print(f"... Constrainer {constrainer} for component {abstraction}")

            r, info = constrainer.solve(abstraction, b"foobar_output", state, behaviors, constraints)
            if r is False:
                # unsat
                return None
            # sat!
            behaviors = info["behaviors"]
            state = info["input_state"]
            input = info["input"]
            constraints = info["constraints"]

            if input is not None:
                inputs.append(info)
                break
        else:
            print(f"... No constrainer can constrain component {component}. You should provide better constrainers!")
            inputs.append(None)

    return inputs


def verify_in_simulation(cps, cpv_model, cpv_desc, cpv_input) -> bool:
    """
    Verify the existence of a CPV input in a customized simulation.
    """
    return False


def process(cps, database, initial_state):

    ##### CPV Matching #####
    # identify potential CPV in CPS
    identified_cpv_and_paths = [ ]
    for cpv_model_base in database["cpv_model"]:
        cpv_model, cpv_paths = identify(cps, initial_state, cpv_model=cpv_model_base)
        if cpv_paths is not None:
            identified_cpv_and_paths.append((cpv_model, cpv_paths))

    # for each identified CPV, constrain further with back-propagated output and constraints to find a possible input
    cpv_inputs = [ ]
    for cpv_model, cpv_paths in identified_cpv_and_paths:
        for cpv_path in cpv_paths:
            cpv_input = constrain_cpv_path(cps, cpv_model, cpv_path)
            if cpv_input is not None:
                cpv_inputs.append((cpv_model, cpv_path, cpv_input))

    # TODO NOW: right now a single mavlink authentication cannot crash the drone.
    # We need to add SiK specification, and component identification

    l.info("Identifying CPVs from CPSVs in database\n")
    ##### CPSV Matching #####
    # for each CPSV, identify potenetial combinations on the target CPS
    # 1. identify if the CPS contains the CPSV
    potential_cpsvs = list(filter(lambda cpsv: cpsv.exists(cps), database['cpsv_model']))

    # 2. generate combinations of CPSVs into CPV 
    cpv_inputs += identify_from_cpsv(cps, potential_cpsvs, initial_state)
        
    # verify each CPV input in customized simulation
    # TODO: connect this with TA2
    l.info("Simulating Identified CPVs\n")
    all_cpvs = []
    for cpv_model, cpv_desc, cpv_input in cpv_inputs:
        verified = verify_in_simulation(cps, cpv_model, cpv_desc, cpv_input)
        all_cpvs.append((cps, cpv_model, cpv_desc, cpv_input, verified))

    return all_cpvs


def main():
    # input: the CPS model
    cps_components = ...

    cps = PX4Quadcopter()
    components = [c() for c in cps.components]
    initial_state = GlobalState(components=components)

    # input: the database with CPV models and CPS vulnerabilities
    database = {
        "cpv_model": [MavlinkCPV()],
        "cpsv_model": [MavlinkCPSV(), SiKCPSV()],
        "cps_vuln": [],
    }

    all_cpvs = process(cps, database, initial_state)
    print(all_cpvs)


if __name__ == "__main__":
    main()
