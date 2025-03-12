import sys
import subprocess
from copy import deepcopy

import unittest
from typing import Optional

import saci
from saci.modeling import CPV, ComponentBase
from saci.modeling.annotation import Annotation
from saci.modeling.device.sensor.compass import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.device.motor.motor import Motor
from saci.modeling.device.interface.serial import Serial
from saci.modeling.device.gcs import GCS
from saci.modeling.state import GlobalState
from saci.modeling.device import ComponentID, MultiCopterMotor, Wifi, SikRadio
from saci.orchestrator import process, identify
from saci.hypothesis import Hypothesis, ParameterAssumption, RemoveComponentsAssumption, AddComponentAssumption
from saci.identifier import IdentifierCPV

from saci_db.cpvs import MavlinkSiKCPV, SerialRollOverCPV, CompassPermanentSpoofingCPV, WifiWebCrashCPV
from saci_db.devices.ngcrover import NGCRover
from saci_db.vulns import LackWifiAuthenticationVuln, MavlinkMitmVuln
from saci_db.devices.px4_quadcopter_device import PX4Quadcopter


def generate_fake_data():
    cps = PX4Quadcopter()
    initial_state = GlobalState(cps.components)

    # input: the database with CPV models and CPS vulnerabilities
    database = {
        "cpv_model": [MavlinkSiKCPV()],
        "cpsv_model": [MavlinkMitmVuln()],
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
        _, cpv_paths = identify(cps, initial_state, cpv_model=MavlinkSiKCPV())
        path = cpv_paths[0].path
        self.assertIsInstance(path[0].component, GCS)
        self.assertIsInstance(path[-1].component, MultiCopterMotor)

    def test_identifier_rover(self):
        cps = NGCRover()
        initial_state = GlobalState(cps.components)
        # this rover sure is vulnerable
        cpv_hypotheses: list[tuple[CPV, Optional[tuple[type[ComponentBase], type[ComponentBase]]]]] = [
            (MavlinkSiKCPV(), None),
            # TODO: restore some sort of the abstraction levels in the identification process
            (SerialRollOverCPV(), (Serial, Motor)),
            (CompassPermanentSpoofingCPV(), (CompassSensor, Steering)),
            (WifiWebCrashCPV(), (Wifi, Motor)),
        ]
        for cpv, endpoints in cpv_hypotheses:
            _, cpv_paths = identify(cps, initial_state, cpv_model=cpv)
            if endpoints is not None:
                start, end = endpoints
                self.assertIsNotNone(cpv_paths)
                self.assertGreater(len(cpv_paths), 0)
                for cpv_path in cpv_paths:
                    self.assertIsInstance(cpv_path.path[0].component, start)
                    self.assertIsInstance(cpv_path.path[-1].component, end)
            else:
                self.assertIsNone(cpv_paths)

    def test_gps_spoofying_hypothesis(self):
        cps = NGCRover()
        self.assertEqual(
            set(cps.components),
            {ComponentID(id_) for id_ in {'wifi', 'webserver', 'gps', 'compass', 'uno_r4', 'serial', 'uno_r3', 'pwm_channel_esc', 'pwm_channel_servo', 'esc', 'steering', 'motor'}},
            "Looks like we added or removed some components from the NGCRover device model. Fix this test appropriately.",
        )
        self.assertNotIn(
            "signal_strength_threshold",
            cps.components[ComponentID("gps")].parameters,
            "Oops, looks like we added a GPS signal strength threshold to the NGCRover device model. Fix this test to use some other unset parameter.",
        )

        threshold = -70
        hypothesis = Hypothesis(
            description="Test",
            path=[],
            assumptions=[
                ParameterAssumption(
                    description="Assume that the GPS receiver is pretty sensitive.",
                    component_id=ComponentID("gps"),
                    parameter_name="signal_strength_threshold",
                    parameter_value=threshold,
                ),
                RemoveComponentsAssumption(
                    description="Let's not model anything but the components on the CPV path for now",
                    component_ids=frozenset({ComponentID(id_) for id_ in {'wifi', 'webserver'}}),
                ),
            ],
        )
        transformed_cps = hypothesis.transform(cps)
        self.assertNotIn(
            "signal_strength_threshold",
            cps.components[ComponentID("gps")].parameters,
            "The device didn't get copied correctly and so transforming the copy also transformed the original. Womp womp.",
        )
        self.assertIn(
            "signal_strength_threshold",
            transformed_cps.components[ComponentID("gps")].parameters,
            "Hm, the hypothesis didn't set the parameter in the rewritten CPS at all.",
        )
        self.assertEqual(
            transformed_cps.components[ComponentID("gps")].parameters["signal_strength_threshold"],
            threshold,
            "... the hypothesis transformation set the parameter to *something* but not the specified value? How did that manage to happen?",
        )
        self.assertEqual(
            set(transformed_cps.components),
            {ComponentID(id_) for id_ in {'gps', 'compass', 'uno_r4', 'serial', 'uno_r3', 'pwm_channel_esc', 'pwm_channel_servo', 'esc', 'steering', 'motor'}},
            "Looks like we added or removed some components from the NGCRover device model. Fix this test appropriately.",
        )

    def test_compvuln_effects(self):
        cps = NGCRover()
        # Let's say we don't know a priori that we can access the wifi interface. Soon we'll update the actual device
        # model for this assumption but now we'll just set it manually.
        cps.component_graph.nodes[ComponentID("wifi")]["is_entry"] = False

        wifi_auth_vuln = LackWifiAuthenticationVuln()
        copied_cps = deepcopy(cps)
        self.assertFalse(
            copied_cps.component_graph.nodes[ComponentID("wifi")]["is_entry"],
            "Did changed component graph attributes not get copied over?",
        )
        self.assertTrue(
            wifi_auth_vuln.exists(copied_cps),
            "Wifi auth vuln not found on the NGCRover.",
        )
        wifi_auth_vuln.apply_effects(copied_cps)
        # The open wifi authentication should allow the wifi component to be an entry point now.
        self.assertTrue(
            copied_cps.component_graph.nodes[ComponentID("wifi")]["is_entry"],
            "Wifi auth vuln did not apply the expected effect despite indicating existence.",
        )

        # Make sure the CPV-based identifier is applying component vulnerabilities' effects
        initial_state = GlobalState(cps.components)
        cpv = WifiWebCrashCPV()
        _, cpv_paths_without_vulns = identify(cps, initial_state, cpv_model=cpv, vulns=[])
        self.assertIn(
            cpv_paths_without_vulns,
            (None, []),
            "Shouldn't be able to find a wifi-based CPV when the wifi module isn't an entry point"
        )
        vulns = [wifi_auth_vuln]
        _, cpv_paths_with_vulns = identify(cps, initial_state, cpv_model=cpv, vulns=vulns)
        self.assertIsNotNone(
            cpv_paths_with_vulns,
            "Should find a wifi-based CPV when the wifi auth vuln adds wifi as an entry point"
        )
        self.assertGreater(
            len(cpv_paths_with_vulns), # type: ignore
            0,
            "Should find a wifi-based CPV when the wifi auth vuln adds wifi as an entry point"
        )

    def test_identifier_hypothesis(self):
        cps = NGCRover()
        # Let's say we don't know a priori that we can access the wifi interface. Soon we'll update the actual device
        # model for this assumption but now we'll just set it manually.
        cps.component_graph.nodes[ComponentID("wifi")]["is_entry"] = False

        wifi_auth_vuln = LackWifiAuthenticationVuln()
        self.assertTrue(
            wifi_auth_vuln.exists(cps),
            "Wifi auth vuln not found on the NGCRover.",
        )
        effects = wifi_auth_vuln.effects(cps)
        self.assertEqual(
            len(effects),
            1,
            "Oops, fix this test to take into account that LackWifiAuthenticationVuln returns more (or fewer?) than one effect now."
        )
        effect = effects[0]

        wifi_web_crash_path = [
            ComponentID("wifi"),
            ComponentID("webserver"),
            ComponentID("uno_r4"),
            ComponentID("uno_r3"),
            ComponentID("pwm_channel_esc"),
            ComponentID("esc"),
            ComponentID("motor"),
        ]
        cpv = WifiWebCrashCPV()
        state = GlobalState(cps.components)
        identifier = IdentifierCPV(cps, state)

        # Verify that with no annotations added, the WifiWebCrashCPV doesn't match, since we can't access the wifi AP.
        hypothesis_no_annotations = Hypothesis(
            description="Null hypothesis (lol)",
            path=wifi_web_crash_path,
        )
        self.assertFalse(
            identifier.check_hypothesis(cpv, hypothesis_no_annotations),
            "Without annotations, the hypothesis shouldn't find a match, but it did!"
        )

        # Verify that with an annotation added that has the effects of LackWifiAuthenticationVuln, the WifiWebCrashCPV
        # does match, since we can access the wifi AP in the transformed device.
        hypothesis_with_annotations = Hypothesis(
            description="Null hypothesis (lol)",
            path=wifi_web_crash_path,
            annotations=[Annotation(
                attack_surface=ComponentID("wifi"),
                underlying_vulnerability=None, # we could put wifi_auth_vuln here but it's not needed
                effect=effect,
                attack_model="foo",
            )],
        )
        self.assertTrue(
            identifier.check_hypothesis(cpv, hypothesis_with_annotations),
            "With annotations, the hypothesis should find a match, but it didn't!"
        )

if __name__ == "__main__":
    unittest.main(argv=sys.argv)
