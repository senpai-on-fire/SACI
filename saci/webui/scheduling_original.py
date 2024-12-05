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


def cpv_search_worker(cps=None, cpv: str=None, search_id=None, hypothesis=None, **kwargs):
    initial_state = GlobalState(cps.components)

    from saci_db.cpvs import CPVS

    cpv_model = None
    for cpv_ in CPVS:
        if cpv_.__class__.__name__ == cpv:
            cpv_model = cpv_
            break

    if cpv_model is None and hypothesis is None:
        # no CPV is found
        update_search_result(search_id, result=f"No CPV is found for {cpv}")
        return

    ta4_queue = queue.Queue()
    ta1 = TA1(ta4_queue)
    ta2 = TA2(ta4_queue)
    ta3 = TA3(ta4_queue)

    if hypothesis is not None:
        hypotheses = [hypothesis]
    else:
        hypotheses = None

    print(hypotheses)
    database = {
        "hypotheses": hypotheses,
        "cpv_model": [cpv_model] if cpv_model is not None else [],
        "cpsv_model": [],
        "cps_vuln": [],
    }
    process_output = process(cps, database, initial_state)
    cpv_inputs = [
        {"cpv_model": cpv_model, "cpv_path": cpv_path, "cpv_input": cpv_input}
        for (_, cpv_model, cpv_path, cpv_input, _)
        in process_output
    ]

    # write identified CPV and paths back
    print(cpv_inputs)
    if cpv_inputs:
        update_search_result(search_id, result="CPV path candidates identified.")
    else:
        update_search_result(search_id, result="No CPV path candidates are identified.")
        return

    # write CPV inputs back
    print(cpv_inputs)
    update_search_result(search_id, cpv_inputs=cpv_inputs)
    update_search_result(search_id, result="CPV input identified.")

    # add the tasks we want the other TAs to do
    # TODO: make this thread exit at some point
    # TODO: this is janky bc we are sending the same object each time... but i don't think there's really any multithreading issues here
    tasks = []
    print("getting tasks")
    while True:
        task = ta4_queue.get()
        print(f"task: {task}")
        tasks.append(task)
        update_search_result(search_id, tasks=tasks)


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
