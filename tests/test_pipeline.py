import sys
import subprocess

import unittest
from typing import Optional

import saci
from saci.modeling import CPV, ComponentBase
from saci.modeling.device.compass import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.device.motor.motor import Motor
from saci.modeling.device.serial import Serial
from saci.modeling.state import GlobalState
from saci.modeling.device import MultiCopterMotor, Wifi, SikRadio
from saci.orchestrator import process, identify

from saci_db.cpvs import MavlinkCPV
from saci_db.cpvs.cpv06_serial_motor_rollover import RollOverCPV
from saci_db.cpvs.cpv07_pmagnet_compass_dos import PermanentCompassSpoofingCPV
from saci_db.cpvs.cpv08_wifi_webserver_crash import WebCrashCPV
from saci_db.devices.ngcrover import NGCRover
from saci_db.vulns import MavlinkCPSV
from saci_db.devices.px4_quadcopter_device import PX4Quadcopter


def generate_fake_data():
    cps = PX4Quadcopter()
    initial_state = GlobalState(cps.components)

    # input: the database with CPV models and CPS vulnerabilities
    database = {
        "cpv_model": [MavlinkCPV()],
        "cpsv_model": [MavlinkCPSV()],
        "cps_vuln": [],
        "hypotheses": []
    }
    return cps, database, initial_state


class TestPipeline(unittest.TestCase):
    def test_end_to_end(self):
        cps, database, initial_state = generate_fake_data()
        try:
            all_cpvs = process(cps, database, initial_state)
        except TypeError:
            # TODO: implement a real constrainer to avoid this exception
            pass

    def test_cli(self):
        output = subprocess.run(["saci", "-v"], capture_output=True)
        version_string = output.stdout.decode("utf-8").strip()
        self.assertEqual(version_string, saci.__version__)

    def test_identifier_mavlink_cpv(self):
        cps, _, initial_state = generate_fake_data()
        _, cpv_paths = identify(cps, initial_state, cpv_model=MavlinkCPV())
        path = cpv_paths[0].path
        self.assertIsInstance(path[0], SikRadio)
        self.assertIsInstance(path[-1], MultiCopterMotor)

    def test_identifier_rover(self):
        cps = NGCRover()
        initial_state = GlobalState(cps.components)
        # this rover sure is vulnerable
        cpv_hypotheses: list[tuple[CPV, Optional[tuple[type[ComponentBase], type[ComponentBase]]]]] = [
            (MavlinkCPV(), None),
            # TODO: restore some sort of the abstraction levels in the identification process
            (RollOverCPV(), (Serial, Motor)),
            (PermanentCompassSpoofingCPV(), (CompassSensor, Steering)),
            (WebCrashCPV(), (Wifi, Motor)),
        ]
        for cpv, endpoints in cpv_hypotheses:
            _, cpv_paths = identify(cps, initial_state, cpv_model=cpv)
            if endpoints is not None:
                start, end = endpoints
                self.assertGreater(len(cpv_paths), 0)
                for cpv_path in cpv_paths:
                    self.assertIsInstance(cpv_path.path[0], start)
                    self.assertIsInstance(cpv_path.path[-1], end)
            else:
                self.assertIsNone(cpv_paths)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
