import networkx as nx

from saci.modeling import Device, Motor

from .gcs_telemetry import GCSTelemetry
from .px4_controller import PX4Controller


class PX4Quadcopter(Device):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "px4_quadcopter"
        self.components = [
            PX4Controller,
            GCSTelemetry,
            Motor
        ]
        self.component_graph = nx.from_edgelist([
            (GCSTelemetry, PX4Controller),
            (PX4Controller, Motor),
        ], create_using=nx.DiGraph)

