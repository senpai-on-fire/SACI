# SACI
SACI - Software-Aware CPS Identifier

## Installation
```bash
pip install -e .
```

## Usage
To use SACI, you need to provide the following inputs:
- A CPV description file
- A device description file

You can describe both using classes from the `saci` package. 
As an example, we can use the CPV described in [examples/cpv01_mitm_mavlink](./examples/cpv01_mitm_mavlink).

### Device Description
```python
from saci.modeling import Device, Motor

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
```

### CPV Description
```python
from saci.modeling import CPV, Controller, Telemetry, Motor

cpv = CPV(
    # describe the required components for the CPV to function
    required_components=[
        Motor,
        Controller,
        Telemetry,
    ],
    
    # describe the observed state of the system when the CPV was triggered
    observations=[
        Controller(is_powered=True),
        Telemetry(is_powered=True),
        Motor(is_powered=False),
    ],
    
    # describe any system-internal transitions you are aware of that caused the system to reach the observed state
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
```

Now that we have the CPV and the device description, we can use SACI to identify if the CPV exists in the device.

```python
from saci.identifier import Identifier
from .device import PX4Quadcopter
from .cpv import cpv

identifier = Identifier(PX4Quadcopter(), [cpv])
paths = identifier.identify()
```