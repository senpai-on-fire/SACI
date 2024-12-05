from time import sleep
from typing import List, Optional, Tuple

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

from saci_db.devices.ngcrover import NGCRover
from saci_db.devices.px4_quadcopter_device import PX4Quadcopter
from saci_db.devices.gs_quadcopter import GSQuadcopter

from saci.modeling.cpv import CPV
from saci.modeling.state import GlobalState
from saci.modeling.behavior import Behaviors
from saci.modeling.cpvpath import CPVPath
from saci.identifier import IdentifierCPV

cpv_database = [MavlinkCPV(), WiFiDeauthDosCPV(), RollOverCPV(), PermanentCompassSpoofingCPV(), WebCrashCPV(),GPSPositionStaticCPV(), 
                ThrottleCPV(), WebMoveCPV(), GPSPositionLoopCPV(), SerialArduinoControlCPV(), WebStopCPV(), RedirectCPV(),
                TemporaryCompassSpoofingCPV(), 
                SMBusBatteryShutdownCPV(), ESCFlashCPV(), ESCBootloaderCPV(), ESCResetCPV(), DischargeCPV(), OverflowCPV(), ESCExeccmdCPV(), OverheatingCPV(),
                GPSCPV(), ICMPFloodingCPV(), MavlinkDisarmCPV(), WiFiDeauthQuadDosCPV(),
                ObjectTrackCPV(), ProjectorOpticalFlowCPV(), DepthCameraDoSCPV()]

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
