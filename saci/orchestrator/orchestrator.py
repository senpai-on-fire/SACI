from typing import Optional, List

from ..constrainers import get_constrainer
from ..modeling.device import ComponentBase, CyberComponentBinary
from ..modeling.state import GlobalState
from ..identifier import Identifier

from saci_db.devices.px4_quadcopter_device import PX4Quadcopter
from saci_db.cpvs import MavlinkCPV


class Behaviors:
    """
    Describes a list of behaviors.
    """

    def __init__(self):
        pass


class CPVPath:
    def __init__(self, path, behaviors):
        self.path: List[ComponentBase] = path
        self.final_behaviors: Behaviors = behaviors


def identify(cps, cpv_model, initial_state) -> List[CPVPath]:
    """
    Identify if the given CPV model may exist in the CPS model. Return a CPV description if it exists, otherwise return
    None.
    """
    identifier = Identifier(cps, initial_state)
    to_return = []
    for path in identifier.identify(cpv_model):
        to_return.append(CPVPath(path, Behaviors()))
    return to_return


def constrain_cpv_path(cps, cpv_model, cpv_path) -> Optional:
    """
    Constrain a CPV path on a CPV model with the goal of generating
    """
    behaviors = cpv_path.final_behaviors
    state = None  # TODO:
    constraints = set()  # TODO:

    inputs = [ ]
    for component in cpv_path.path:
        constrainer_clses = list(get_constrainer(component))
        if not constrainer_clses:
            raise TypeError(f"No constrainer found for {component}")

        # FIXME: We are taking the last class
        constrainer = constrainer_clses[-1]()
        r, info = constrainer.solve(state, behaviors, constraints)
        if r is False:
            # unsat
            return None
        # sat!
        behaviors = info["behaviors"]
        state = info["input_state"]
        input = info["input"]
        constraints = info["constraints"]

        inputs.append(input)

    return inputs


def verify_in_simulation(cps, cpv_model, cpv_desc, cpv_input) -> bool:
    """
    Verify the existence of a CPV input in a customized simulation.
    """
    return False


def process(cps, database, initial_state):

    # identify potential CPV in CPS
    identified_cpv_and_paths = [ ]
    for cpv_model in database["cpv_model"]:
        cpv_paths = identify(cps, cpv_model, initial_state)
        if cpv_paths is not None:
            identified_cpv_and_paths.append((cpv_model, cpv_paths))

    # for each identified CPV, constrain further with back-propagated output and constraints to find a possible input
    cpv_inputs = [ ]
    for cpv_model, cpv_paths in identified_cpv_and_paths:
        for cpv_path in cpv_paths:
            cpv_input = constrain_cpv_path(cps, cpv_model, cpv_path)
            if cpv_input is not None:
                cpv_inputs.append((cpv_model, cpv_path, cpv_input))

    # verify each CPV input in customized simulation
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
        "cps_vuln": [],
    }

    all_cpvs = process(cps, database, initial_state)
    print(all_cpvs)


if __name__ == "__main__":
    main()
