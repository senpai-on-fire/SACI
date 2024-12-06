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

from saci_db.cpvs.cpv01_sik_mavlink_motors import MavlinkCPV
from saci_db.cpvs.cpv02_gps_position_move import GPSCPV
from saci_db.cpvs.cpv03_deauth_dos import WiFiDeauthDosCPV
from saci_db.cpvs.cpv04_icmp_cpv import ICMPFloodingCPV
from saci_db.cpvs.cpv05_adv_ml_untrack import ObjectTrackCPV
from saci_db.cpvs.cpv06_serial_motor_rollover import RollOverCPV
from saci_db.cpvs.cpv07_pmagnet_compass_dos import PermanentCompassSpoofingCPV
from saci_db.cpvs.cpv08_wifi_webserver_crash import WebCrashCPV
from saci_db.cpvs.cpv09_gps_position_static import GPSPositionStaticCPV
from saci_db.cpvs.cpv11_serial_motor_throttle import ThrottleCPV
from saci_db.cpvs.cpv12_wifi_http_move import WebMoveCPV
from saci_db.cpvs.cpv13_gps_position_loop import GPSPositionLoopCPV
from saci_db.cpvs.cpv14_serial_arduino_control import SerialArduinoControlCPV
from saci_db.cpvs.cpv15_wifi_http_stop import WebStopCPV
from saci_db.cpvs.cpv16_serial_motor_redirect import RedirectCPV
from saci_db.cpvs.cpv17_tmagnet_compass_disorient import TemporaryCompassSpoofingCPV
from saci_db.cpvs.cpv18_smbus_battery_shutdown import SMBusBatteryShutdownCPV
from saci_db.cpvs.cpv19_debug_esc_flash import ESCFlashCPV
from saci_db.cpvs.cpv20_serial_esc_bootloader import ESCBootloaderCPV
from saci_db.cpvs.cpv21_serial_esc_reset import ESCResetCPV
from saci_db.cpvs.cpv22_serial_esc_discharge import DischargeCPV
from saci_db.cpvs.cpv23_serial_esc_bufferoverflow import OverflowCPV
from saci_db.cpvs.cpv24_serial_esc_execcmd import ESCExeccmdCPV
from saci_db.cpvs.cpv25_serial_motor_overheat import OverheatingCPV
from saci_db.cpvs.cpv30_projector_opticalflow_dos import ProjectorOpticalFlowCPV
from saci_db.cpvs.cpv31_laser_depthcamera_dos import DepthCameraDoSCPV
from saci_db.cpvs.cpv33_deauth_quad_dos import WiFiDeauthQuadDosCPV
from saci_db.cpvs.cpv34_wifi_mavlink_disarm import MavlinkDisarmCPV

cpv_database = [MavlinkCPV(), WiFiDeauthDosCPV(), RollOverCPV(), PermanentCompassSpoofingCPV(), WebCrashCPV(),GPSPositionStaticCPV(), 
                ThrottleCPV(), WebMoveCPV(), GPSPositionLoopCPV(), SerialArduinoControlCPV(), WebStopCPV(), RedirectCPV(),
                TemporaryCompassSpoofingCPV(), 
                SMBusBatteryShutdownCPV(), ESCFlashCPV(), ESCBootloaderCPV(), ESCResetCPV(), DischargeCPV(), OverflowCPV(), ESCExeccmdCPV(), OverheatingCPV(),
                GPSCPV(), ICMPFloodingCPV(), MavlinkDisarmCPV(), WiFiDeauthQuadDosCPV(),
                ObjectTrackCPV(), ProjectorOpticalFlowCPV(), DepthCameraDoSCPV()]


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
