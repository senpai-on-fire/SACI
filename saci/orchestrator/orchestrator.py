from typing import Optional


def identify(cps, cpv_model) -> Optional:
    """
    Identify if the given CPV model exists in the CPS model. Return a CPV description if it exists, otherwise return
    None.
    """
    return None


def desc_to_input(cps, cpv_model, cpv_desc) -> Optional:
    """
    Convert a CPV description to some input.
    """
    return None


def verify_in_simulation(cps, cpv_model, cpv_desc, cpv_input) -> bool:
    """
    Verify the existence of a CPV input in a customized simulation.
    """
    return False


def process(cps, database):

    # identify potential CPV in CPS
    identified_cpvs = [ ]
    for cpv_model in database["cpv_model"]:
        cpv_desc = identify(cps, cpv_model)
        if cpv_desc is not None:
            identified_cpvs.append((cpv_model, cpv_desc))

    # for each identified CPV, find input
    cpv_input = [ ]
    for cpv_model, cpv_desc in identified_cpvs:
        cpv_input = desc_to_input(cps, cpv_model, cpv_desc)
        if cpv_input is not None:
            cpv_input.append((cpv_model, cpv_desc, cpv_input))

    # verify each CPV input in customized simulation
    all_cpvs = []
    for cpv_model, cpv_desc, cpv_input in cpv_input:
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
        "cpv_model": [],
        "cps_vuln": [],
    }

    all_cpvs = process(cps, database)


if __name__ == "__main__":
    main()
