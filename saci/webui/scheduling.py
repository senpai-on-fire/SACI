from __future__ import annotations

import time
import threading

from saci.modeling.state import GlobalState
from saci.orchestrator.orchestrator import identify, constrain_cpv_path, identify_from_cpsv


WORK_THREAD = None
SEARCHES: dict[int, dict] = {}


def add_search(**kwargs) -> int:
    # TODO: add lock

    max_id = 0
    if SEARCHES:
        max_id = max(SEARCHES) + 1

    search = {
        "taken": False,
        "search_id": max_id,
    } | kwargs

    SEARCHES[max_id] = search
    return max_id


def update_search_result(search_id: int, **kwargs) -> None:
    global SEARCHES

    search = SEARCHES[search_id]
    for k, v in kwargs.items():
        search[k] = v
    search["last_updated"] = int(time.time() * 10000)


def cpv_search_worker(cpv=None, search_id=None, **kwargs):

    from saci_db.devices.px4_quadcopter_device import PX4Quadcopter
    cps = PX4Quadcopter()

    initial_state = GlobalState(cps.components)

    from saci_db.cpvs.cpv01_mavlink_motors import MavlinkCPV
    cpv = MavlinkCPV()  # TODO: Use the one that is passed in


    # Identify CPV models and CPV paths
    identified_cpv_and_paths = []

    cpv_model, cpv_paths = identify(cps, initial_state, cpv_model=cpv)
    if cpv_model is not None and cpv_paths is not None:
        identified_cpv_and_paths.append((cpv_model, cpv_paths))

    from saci_db.vulns import MavlinkCPSV, MavlinkOverflow
    potential_cpsvs = list(filter(lambda cpsv: cpsv.exists(cps), [MavlinkCPSV(), MavlinkOverflow()]))
    identified_cpv_and_paths += identify_from_cpsv(cps, potential_cpsvs, initial_state)

    # write identified CPV and paths back
    print(identified_cpv_and_paths)
    update_search_result(search_id, identified_cpv_and_paths=identified_cpv_and_paths)

    # Constrain identified CPV paths
    # for each identified CPV, constrain further with back-propagated output and constraints to find a possible input
    cpv_inputs = [ ]
    for cpv_model, cpv_paths in SEARCHES[search_id]["identified_cpv_and_paths"]:
        for cpv_path in cpv_paths:
            cpv_input = constrain_cpv_path(cps, cpv_model, cpv_path)
            if cpv_input is not None:
                cpv_inputs.append((cpv_model, cpv_path, cpv_input))

    # write CPV inputs back
    print(cpv_inputs)
    update_search_result(search_id, cpv_inputs=cpv_inputs)


def working_routine():
    while True:
        time.sleep(1)
        for idx in list(SEARCHES):
            search = SEARCHES[idx]
            if search.get("taken", None) is False:
                search["taken"] = True

                search["thread"] = threading.Thread(target=cpv_search_worker, kwargs=search, daemon=True)
                search["thread"].start()


def start_work_thread():
    global WORK_THREAD

    WORK_THREAD = threading.Thread(target=working_routine, daemon=True)
    WORK_THREAD.start()
