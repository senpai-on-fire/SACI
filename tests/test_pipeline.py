import sys
import subprocess

import unittest

import saci
from saci.modeling.state import GlobalState
from saci.modeling.device import MultiCopterMotorHigh
from saci.orchestrator import process, identify

from saci_db.cpvs import MavlinkCPV
from saci_db.devices.px4_quadcopter_device import PX4Quadcopter, GCSTelemetryHigh


def generate_fake_data():
    cps = PX4Quadcopter()
    components = [c() for c in cps.components]
    initial_state = GlobalState(components=components)

    # input: the database with CPV models and CPS vulnerabilities
    database = {
        "cpv_model": [MavlinkCPV()],
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
        assert version_string == saci.__version__

    def test_identifier_mavlink_cpv(self):
        cps, _, initial_state = generate_fake_data()
        cpv_paths = identify(cps, MavlinkCPV(), initial_state)
        path = cpv_paths[0].path
        assert isinstance(path[0], GCSTelemetryHigh)
        assert isinstance(path[-1], MultiCopterMotorHigh)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
