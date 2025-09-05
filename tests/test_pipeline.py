import sys
import subprocess
from copy import deepcopy

import unittest

import networkx as nx

import saci
from saci.modeling import CPV, ComponentBase
from saci.modeling.annotation import Annotation
from saci.modeling.device.sensor.compass import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.device.motor.motor import Motor
from saci.modeling.device.interface.serial import Serial
from saci.modeling.device.gcs import GCS
from saci.modeling.device import Device
from saci.modeling.state import GlobalState
from saci.modeling.device import ComponentID, MultiCopterMotor, Wifi
from saci.orchestrator import process, identify
from saci.hypothesis import Hypothesis, ParameterAssumption, RemoveComponentsAssumption
from saci.identifier import IdentifierCPV

from saci_db.cpvs import MavlinkSiKCPV, SerialRollOverCPV, CompassPermanentSpoofingCPV, WifiWebCrashCPV
from saci_db.devices.ngcrover import NGCRover
from saci_db.vulns import LackWifiAuthenticationVuln, MavlinkMitmVuln
from saci_db.devices.px4_quadcopter_device import PX4Quadcopter


def generate_fake_data():
    cps = PX4Quadcopter()
    initial_state = GlobalState(cps.components)

    # input: the database with CPV models and CPS vulnerabilities
    database = {"cpv_model": [MavlinkSiKCPV()], "cpsv_model": [MavlinkMitmVuln()], "cps_vuln": [], "hypotheses": []}
    return cps, database, initial_state


class TestPipeline(unittest.TestCase):
    def test_end_to_end(self):
        cps, database, initial_state = generate_fake_data()
        try:
            process(cps, database, initial_state)
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
        self.assertIsNotNone(cpv_paths)
        if cpv_paths is not None:
            self.assertGreater(len(cpv_paths), 0)
            path = cpv_paths[0].path
            self.assertIsInstance(path[0].component, GCS)
            self.assertIsInstance(path[-1].component, MultiCopterMotor)

    def test_identifier_rover(self):
        cps = NGCRover()
        initial_state = GlobalState(cps.components)
        # this rover sure is vulnerable
        cpv_hypotheses: list[tuple[CPV, tuple[type[ComponentBase], type[ComponentBase]] | None]] = [
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
                if cpv_paths is not None:
                    self.assertGreater(len(cpv_paths), 0)
                    for cpv_path in cpv_paths:
                        self.assertIsInstance(cpv_path.path[0].component, start)
                        self.assertIsInstance(cpv_path.path[-1].component, end)
            else:
                self.assertTrue(cpv_paths is None or len(cpv_paths) == 0)

    def test_gps_spoofying_hypothesis(self):
        cps = NGCRover()
        self.assertEqual(
            set(cps.components),
            {
                ComponentID(id_)
                for id_ in {
                    "wifi",
                    "webserver",
                    "gps",
                    "compass",
                    "uno_r4",
                    "serial",
                    "uno_r3",
                    "pwm_channel_esc",
                    "pwm_channel_servo",
                    "esc",
                    "steering",
                    "motor",
                }
            },
            "NGCRover components changed.",
        )
        self.assertNotIn(
            "signal_strength_threshold",
            cps.components[ComponentID("gps")].parameters,
            "Unexpected GPS signal strength threshold parameter.",
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
                    component_ids=frozenset({ComponentID(id_) for id_ in {"wifi", "webserver"}}),
                ),
            ],
        )
        transformed_cps = hypothesis.transform(cps)
        self.assertNotIn(
            "signal_strength_threshold",
            cps.components[ComponentID("gps")].parameters,
            "Device copy failed; original was mutated.",
        )
        self.assertIn(
            "signal_strength_threshold",
            transformed_cps.components[ComponentID("gps")].parameters,
            "Parameter not set in transformed CPS.",
        )
        self.assertEqual(
            transformed_cps.components[ComponentID("gps")].parameters["signal_strength_threshold"],
            threshold,
            "Parameter set incorrectly in transformed CPS.",
        )
        self.assertEqual(
            set(transformed_cps.components),
            {
                ComponentID(id_)
                for id_ in {
                    "gps",
                    "compass",
                    "uno_r4",
                    "serial",
                    "uno_r3",
                    "pwm_channel_esc",
                    "pwm_channel_servo",
                    "esc",
                    "steering",
                    "motor",
                }
            },
            "Transformed NGCRover components changed.",
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
            "Component graph attributes not copied.",
        )
        self.assertTrue(
            wifi_auth_vuln.exists(copied_cps),
            "Wifi auth vuln not found.",
        )
        wifi_auth_vuln.apply_effects(copied_cps)
        self.assertTrue(
            copied_cps.component_graph.nodes[ComponentID("wifi")]["is_entry"],
            "Wifi auth vuln effect not applied.",
        )

        # Make sure the CPV-based identifier is applying component vulnerabilities' effects
        initial_state = GlobalState(cps.components)
        cpv = WifiWebCrashCPV()
        _, cpv_paths_without_vulns = identify(cps, initial_state, cpv_model=cpv, vulns=[])
        self.assertIn(
            cpv_paths_without_vulns,
            (None, []),
            "Shouldn't find wifi-based CPV without entry point.",
        )
        vulns = [wifi_auth_vuln]
        _, cpv_paths_with_vulns = identify(cps, initial_state, cpv_model=cpv, vulns=vulns)
        self.assertIsNotNone(
            cpv_paths_with_vulns,
            "Should find wifi-based CPV with vuln.",
        )
        self.assertGreater(
            len(cpv_paths_with_vulns),  # type: ignore
            0,
            "Should find wifi-based CPV with vuln.",
        )

    def test_identifier_hypothesis(self):
        cps = NGCRover()
        # Let's say we don't know a priori that we can access the wifi interface. Soon we'll update the actual device
        # model for this assumption but now we'll just set it manually.
        cps.component_graph.nodes[ComponentID("wifi")]["is_entry"] = False

        wifi_auth_vuln = LackWifiAuthenticationVuln()
        self.assertTrue(
            wifi_auth_vuln.exists(cps),
            "Wifi auth vuln not found.",
        )
        effects = wifi_auth_vuln.effects(cps)
        self.assertEqual(
            len(effects),
            1,
            "Unexpected number of effects.",
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
            "Should not match without annotations.",
        )

        # Verify that with an annotation added that has the effects of LackWifiAuthenticationVuln, the WifiWebCrashCPV
        # does match, since we can access the wifi AP in the transformed device.
        hypothesis_with_annotations = Hypothesis(
            description="Null hypothesis (lol)",
            path=wifi_web_crash_path,
            annotations=[
                Annotation(
                    attack_surface=ComponentID("wifi"),
                    underlying_vulnerability=None,  # we could put wifi_auth_vuln here but it's not needed
                    effect=effect,
                    attack_model="foo",
                )
            ],
        )
        self.assertTrue(
            identifier.check_hypothesis(cpv, hypothesis_with_annotations),
            "Should match with annotations.",
        )

    def test_device_int_compids(self):
        """Make sure the pipeline basically works with non-string component ID types."""
        cps: Device[ComponentID] = PX4Quadcopter()

        compid_mapping: dict[str, int] = {orig_id: i for i, orig_id in enumerate(cps.components)}
        new_components = {compid_mapping[orig_id]: comp for orig_id, comp in cps.components.items()}
        new_graph = nx.DiGraph()
        for comp_id, data in cps.component_graph.nodes(data=True):
            new_graph.add_node(compid_mapping[comp_id], **data)  # type: ignore
        for from_, to, data in cps.component_graph.edges(data=True):  # type: ignore
            new_graph.add_edge(compid_mapping[from_], compid_mapping[to], **data)  # type: ignore

        new_cps: Device[int] = Device(name="foo", components=new_components, component_graph=new_graph)
        initial_state: GlobalState[int] = GlobalState(new_cps.components)

        _, cpv_paths = identify(cps, initial_state, cpv_model=MavlinkSiKCPV())
        self.assertIsNotNone(cpv_paths)
        self.assertGreater(len(cpv_paths), 0)  # type: ignore
        path = cpv_paths[0].path  # type: ignore
        self.assertIsInstance(path[0].component, GCS)
        self.assertIsInstance(path[-1].component, MultiCopterMotor)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
