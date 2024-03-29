import networkx as nx
from saci.modeling.device import Device, MultiCopterMotorHigh, MultiCopterMotorAlgo

from .gcs_telemetry import GCSTelemetryHigh, GCSTelemetryAlgo
from .px4_controller import PX4ControllerHigh


class PX4Quadcopter(Device):
    def __init__(self, state=None):
        super().__init__(
            name="px4_quadcopter_device",
            components=[
                GCSTelemetryHigh,
                GCSTelemetryAlgo,
                PX4ControllerHigh,
                MultiCopterMotorHigh,
                MultiCopterMotorAlgo
            ],
            high_graph=nx.from_edgelist([
                (GCSTelemetryHigh, PX4ControllerHigh),
                (PX4ControllerHigh, MultiCopterMotorHigh),
            ], create_using=nx.DiGraph),
            state=state,
        )
