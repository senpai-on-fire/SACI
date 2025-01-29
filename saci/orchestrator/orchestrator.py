from time import sleep
from typing import List, Optional, Tuple


from saci_db.cpvs import *

from saci_db.devices.ngcrover import NGCRover
from saci_db.devices.px4_quadcopter_device import PX4Quadcopter
from saci_db.devices.gs_quadcopter import GSQuadcopter

from saci.modeling.cpv import CPV
from saci.modeling.state import GlobalState
from saci.modeling.behavior import Behaviors
from saci.modeling.cpvpath import CPVPath
from saci.identifier import IdentifierCPV

from .cpv_definitions import CPVS as CPVS

import logging
l = logging.getLogger(__name__)

def identify(cps, initial_state, cpv_model: Optional[CPV] = None) -> Tuple[Optional[CPV], Optional[List[CPVPath]]]:
    """
    Identify if the given CPV model may exist in the CPS model.
    Return a CPV description if it exists, otherwise return None.
    """
    identifier = IdentifierCPV(cps, initial_state)
    to_return = []
    for path in identifier.identify(cpv_model):
        to_return.append(CPVPath(path, Behaviors([])))
    if to_return:
        return cpv_model, to_return
    else:
        return None, None

def process(cps, database, initial_state):
    
    identified_cpv_and_paths = [ ]
    
    ##### CPV Matching #####
    l.info("Identifying CPVs from existed CPV database\n")
    for cpv_model_base in database:
        cpv_model, cpv_paths = identify(cps, initial_state, cpv_model=cpv_model_base)
        if cpv_paths is not None:
            identified_cpv_and_paths.append((cpv_model, cpv_paths))
    
    cpv_inputs = [ ]
    for cpv_model, cpv_paths in identified_cpv_and_paths:
        for cpv_path in cpv_paths:
            cpv_inputs.append((cpv_model, cpv_path))
        

    return cpv_inputs

def main():

    # input: the CPS model
    
    cps = PX4Quadcopter()
    #cps = NGCRover()
    #cps = GSQuadcopter()
    # Search CPV from our database
    
    initial_state = GlobalState(components=cps.components)

    # input: the database with CPV models and CPS vulnerabilities
    database = {
        "cpv_model": cpv_database,
        "cps_vuln": [],
        "hypotheses": []
    }

    all_cpvs = process(cps, database, initial_state)

    for i, cpv in enumerate(all_cpvs, start=0):
        print(cpv)

if __name__ == "__main__":
    # TODO: orchestrator should keep receiving new hypotheses and new inputs from each TA.
    main()
