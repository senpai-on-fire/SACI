from __future__ import annotations

import time
import threading

from saci.modeling.state import GlobalState
from saci.orchestrator.orchestrator import identify, constrain_cpv_path, identify_from_cpsv, MOCK_TASKS_1, MOCK_TASKS_2


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


def cpv_search_worker(cps=None, cpv: str=None, search_id=None, **kwargs):
    initial_state = GlobalState(cps.components)

    from saci_db.cpvs import CPVS

    cpv_model = None
    for cpv_ in CPVS:
        if cpv_.__class__.__name__ == cpv:
            cpv_model = cpv_
            break

    if cpv_model is None:
        # no CPV is found
        update_search_result(search_id, result=f"No CPV is found for {cpv}")
        return

    # Identify CPV models and CPV paths
    identified_cpv_and_paths = []

    cpv_model, cpv_paths = identify(cps, initial_state, cpv_model=cpv_model)
    if cpv_model is not None and cpv_paths is not None:
        identified_cpv_and_paths.append((cpv_model, cpv_paths))

    # what is this special casing??
    if "mavlink" in cpv_model.__class__.__name__.lower():
        from saci_db.vulns import MavlinkCPSV, MavlinkOverflow
        potential_cpsvs = list(filter(lambda cpsv: cpsv.exists(cps), [MavlinkCPSV(), MavlinkOverflow()]))
        identified_cpv_and_paths += identify_from_cpsv(cps, potential_cpsvs, initial_state)

    # write identified CPV and paths back
    print(identified_cpv_and_paths)
    if identified_cpv_and_paths:
        update_search_result(search_id, identified_cpv_and_paths=identified_cpv_and_paths)
        update_search_result(search_id, result="CPV path candidates identified.")
    else:
        update_search_result(search_id, result="No CPV path candidates are identified.")
        return

    # Constrain identified CPV paths
    # for each identified CPV, constrain further with back-propagated output and constraints to find a possible input
    cpv_inputs = [ ]
    for cpv_model, cpv_paths in SEARCHES[search_id]["identified_cpv_and_paths"]:
        for cpv_path in cpv_paths:
            cpv_input = constrain_cpv_path(cps, cpv_model, cpv_path, {"goal": getattr(cpv_model, "goal_motor_state", "shut_down")})
            if cpv_input is not None:
                cpv_inputs.append({
                    "cpv_model": cpv_model,
                    "cpv_path": cpv_path,
                    "cpv_input": cpv_input,
                })

    # write CPV inputs back
    print(cpv_inputs)
    update_search_result(search_id, cpv_inputs=cpv_inputs)
    update_search_result(search_id, result="CPV input identified.")

    # add the tasks we want the other TAs to do
    update_search_result(search_id, tasks=MOCK_TASKS_1)
    time.sleep(5.0)
    update_search_result(search_id, tasks=MOCK_TASKS_2)


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
