import networkx as nx

from saci.modeling import Device, Motor, Controller, Telemetry, CPV
from .px4_quadcopter import GCSTelemetry, PX4Controller

cpv = CPV(
    required_components=[
        Motor,
        Controller,
        Telemetry,
    ],
    observations=[
        Controller(is_powered=True),
        Telemetry(is_powered=True),
        Motor(is_powered=False),
    ],
    transitions={
        # overall transitions of the full system
        # telemetry -> controller -> motor
        Device: nx.from_edgelist([
            (Telemetry, Controller),
            (Controller, Motor),
        ], create_using=nx.DiGraph),

        # transitions of the telemetry component:
        # recv -> processing -> notify
        GCSTelemetry: nx.from_edgelist([
            (GCSTelemetry.S_RECV, GCSTelemetry.S_PROCESSING),
            (GCSTelemetry.S_PROCESSING, GCSTelemetry.S_NOTIFY),
        ], create_using=nx.DiGraph),

        # transitions of the controller component
        # accept_notif -> process_notif -> disarm
        PX4Controller: nx.from_edgelist([
            (PX4Controller.S_ACCCEPT_NOTIF, PX4Controller.S_PROCESS_NOTIF),
            (PX4Controller.S_PROCESS_NOTIF, PX4Controller.S_DISARM),
        ], create_using=nx.DiGraph),
    }
)
