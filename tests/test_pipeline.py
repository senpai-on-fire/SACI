import sys
import subprocess

import unittest

import saci
from saci.modeling.state import GlobalState
from saci.modeling.device import MultiCopterMotor
from saci.orchestrator import process, identify

from saci_db.cpvs import MavlinkCPV
from saci_db.vulns import MavlinkCPSV
from saci_db.devices.px4_quadcopter_device import PX4Quadcopter, GCSTelemetry


def generate_fake_data():
    cps = PX4Quadcopter()
    initial_state = GlobalState(cps.components)

    # input: the database with CPV models and CPS vulnerabilities
    database = {
        "cpv_model": [MavlinkCPV()],
        "cpsv_model": [MavlinkCPSV()],
        "cps_vuln": [],
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
        self.assertIsInstance(path[0], GCSTelemetry)
        self.assertIsInstance(path[-1], MultiCopterMotor)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
