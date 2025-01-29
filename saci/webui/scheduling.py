from __future__ import annotations

import json
import queue
import time
import threading
from io import StringIO

from saci.modeling import CPVHypothesis
from saci.modeling.state import GlobalState
from saci.orchestrator import process
#from saci.orchestrator.orchestrator import identify, constrain_cpv_path, identify_from_cpsv, MOCK_TASKS_1, MOCK_TASKS_2
from saci.orchestrator.workers import TA1, TA2, TA3

from saci.orchestrator.cpv_definitions import CPVS as cpv_database

WORK_THREAD = None
SEARCHES: dict[int, dict] = {}

def add_search(**kwargs) -> int:
    global SEARCHES

    max_id = 0
    if SEARCHES:
        max_id = max(SEARCHES) + 1

    search = {
        "taken": False,
        "search_id": max_id,
    } | kwargs

    print("Adding Search:", search)  # Debugging statement

    SEARCHES[max_id] = search
    return max_id


def update_search_result(search_id: int, **kwargs) -> None:
    global SEARCHES

    if search_id not in SEARCHES:
        print(f"Search ID {search_id} not found in SEARCHES.")  # Debugging statement
        return

    search = SEARCHES[search_id]
    for k, v in kwargs.items():
        search[k] = v
    search["last_updated"] = int(time.time() * 10000)

    print("Updated Search Result:", search)  # Debugging statement

def cpv_search_worker(cps=None, search_id=None, **kwargs):
    initial_state = GlobalState(cps.components)
    process_output = process(cps, cpv_database, initial_state)

    # Extract CPV names and IDs only
    associated_cpvs = [
    {"id": idx, "name": cpv_model.NAME, "cls_name": cpv_model.__class__.__name__}
    for idx, (cpv_model, _) in enumerate(process_output)]

    if associated_cpvs:
        update_search_result(search_id, result="CPV candidates identified.", cpv_inputs=associated_cpvs)
    else:
        update_search_result(search_id, result="No CPVs identified.", cpv_inputs=[])


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
