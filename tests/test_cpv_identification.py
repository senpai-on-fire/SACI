import networkx as nx
import pytest

from saci.identifier import IdentifierCPV
from saci.modeling import CPV, Device
from saci.modeling.device import Controller, PWMChannel, Motor
from saci.modeling.device.sensor import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.state import GlobalState
from saci_db.cpvs import Battery


@pytest.fixture
def sample_device() -> Device:
    compass = CompassSensor()
    controller1 = Controller()
    controller2 = Controller()
    pwm = PWMChannel()
    steering = Steering()
    motor = Motor()

    components = [
        compass,
        controller1,
        controller2,
        pwm,
        steering,
        motor,
    ]

    edges = [
        (compass, controller1),
        (controller1, controller2),
        (controller2, pwm),
        (pwm, steering),
        (steering, motor),
    ]

    graph = nx.DiGraph()
    graph.add_edges_from(edges)

    # Set the CompassSensor as an entry point
    graph.nodes[compass]["is_entry"] = True

    return Device("sample device", components, component_graph=graph)


def test_entry_component(sample_device: Device):
    class TestCPV(CPV):
        def __init__(self):
            super().__init__(
                entry_component=CompassSensor(),
            )

    cpv = TestCPV()
    state = GlobalState(components=sample_device.components)
    identifier = IdentifierCPV(sample_device, state)
    assert identifier.identify(cpv)


def test_entry_component_no_entry(sample_device: Device):
    class TestCPV(CPV):
        def __init__(self):
            super().__init__(
                entry_component=Battery(),
            )

    cpv = TestCPV()
    state = GlobalState(components=sample_device.components)
    identifier = IdentifierCPV(sample_device, state)
    assert not identifier.identify(cpv)


def test_exit_component(sample_device: Device):
    class TestCPV(CPV):
        def __init__(self):
            super().__init__(
                exit_component=Motor(),
            )

    cpv = TestCPV()
    state = GlobalState(components=sample_device.components)
    identifier = IdentifierCPV(sample_device, state)
    assert identifier.identify(cpv)


def test_exit_component_no_exit(sample_device: Device):
    class TestCPV(CPV):
        def __init__(self):
            super().__init__(
                exit_component=Battery(),
            )

    cpv = TestCPV()
    state = GlobalState(components=sample_device.components)
    identifier = IdentifierCPV(sample_device, state)
    assert not identifier.identify(cpv)


def test_required_component(sample_device: Device):
    class TestCPV(CPV):
        def __init__(self):
            super().__init__(
                required_components=[
                    CompassSensor(),
                    Controller(),
                    PWMChannel(),
                    Steering(),
                    Motor(),
                ]
            )

    cpv = TestCPV()
    state = GlobalState(components=sample_device.components)
    identifier = IdentifierCPV(sample_device, state)
    assert identifier.identify(cpv)


def test_required_component_missing(sample_device: Device):
    class TestCPV(CPV):
        def __init__(self):
            super().__init__(
                required_components=[
                    CompassSensor(),
                    Controller(),
                    Battery(),  # Missing component
                    PWMChannel(),
                    Steering(),
                    Motor(),
                ]
            )

    cpv = TestCPV()
    state = GlobalState(components=sample_device.components)
    identifier = IdentifierCPV(sample_device, state)
    assert not identifier.identify(cpv)


def test_required_component_out_of_order(sample_device: Device):
    class TestCPV(CPV):
        def __init__(self):
            super().__init__(
                required_components=[
                    CompassSensor(),
                    PWMChannel(),  # Out of order
                    Controller(),
                    Steering(),
                    Motor(),
                ]
            )

    cpv = TestCPV()
    state = GlobalState(components=sample_device.components)
    identifier = IdentifierCPV(sample_device, state)
    assert not identifier.identify(cpv)


def test_required_component_with_extras(sample_device: Device):
    class TestCPV(CPV):
        def __init__(self):
            super().__init__(
                required_components=[
                    CompassSensor(),
                    Motor(),
                ]
            )

    cpv = TestCPV()
    state = GlobalState(components=sample_device.components)
    identifier = IdentifierCPV(sample_device, state)
    assert identifier.identify(cpv)
