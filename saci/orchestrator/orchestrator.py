from typing import Optional, List

from ..constrainers import get_constrainer
from ..modeling.device import ComponentBase


class BaseComponent:
    """
    The base class for all components. Should be replaced by classes in saci.modeling once Zion finishes his job.
    """

    def __init__(self, name, component_type, abstraction_layer):
        self.name = name
        self.type = component_type
        self.abstraction_layer = abstraction_layer

    def __repr__(self):
        return f"<Component {self.name} | {self.type}>"


class Behaviors:
    """
    Describes a list of behaviors.
    """

    def __init__(self):
        pass


class CPVPath:
    def __init__(self, path, behaviors):
        self.path: List[BaseComponent] = path
        self.final_behaviors: Behaviors = behaviors


def identify(cps, cpv_model) -> List[CPVPath]:
    """
    Identify if the given CPV model may exist in the CPS model. Return a CPV description if it exists, otherwise return
    None.
    """
    # TODO: Adam's identifier will be invoked
    return [CPVPath([BaseComponent("prog", "cyber", "binary")], Behaviors())]


def constrain_cpv_path(cps, cpv_model, cpv_path) -> Optional:
    """
    Constrain a CPV path on a CPV model with the goal of generating
    """
    behaviors = cpv_path.final_behaviors
    state = None  # TODO:
    constraints = set()  # TODO:

    inputs = [ ]
    for component in cpv_path.path:
        constrainer_cls = get_constrainer(component)
        if constrainer_cls is None:
            raise TypeError(f"No constrainer found for {component}")

        constrainer = constrainer_cls()
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


def process(cps, database):

    # identify potential CPV in CPS
    identified_cpv_and_paths = [ ]
    for cpv_model in database["cpv_model"]:
        cpv_paths = identify(cps, cpv_model)
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
    cps = {
        "components": cps_components,
    }

    # input: the database with CPV models and CPS vulnerabilities
    database = {
        "cpv_model": ["buggy"],
        "cps_vuln": [],
    }

    all_cpvs = process(cps, database)
    print(all_cpvs)


if __name__ == "__main__":
    main()
