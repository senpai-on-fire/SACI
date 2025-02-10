# SACI
SACI - Software-Aware CPV Identifier

## Installation
For development, install `SACI` and the `saci-db` (located in a submodule) together: 
```bash
pip install -e . './saci-database'
```
[app-controller](https://github.com/twizmwazin/app-controller) also needs to be running in order to support the web UI.

For deployment, use the Kubernetes deploy configuration:
```bash
kubectl apply -f ./deploy.yml
```
and to undeploy:
```bash
kubectl delete -f ./deploy.yml
```
However, deploy.yml uses the latest built containers from GHCR rather than your local source code. We'll address this at some point, hopefully.

## Background
SCAI is used for understanding if a Cyber-Physical Vulnerability (CPV) exists inside a Cyber-Physical Device by
exploring and modeling known CPVs in other devices. 

To do this you must model two things:
1. A Cyber-Physical Device
2. A CPV

### Cyber-Physical Vulnerabilities 
To SACI, a CPV is a cyber vulnerability that is used to achieve a physical goal on the device (like shutting off motors
mid-flight). In order to model a CPV, you must also model a vulnerability which allows for some form of controlled
data in a device. 

### Levels of Abstraction
SACI is built to work with multiple layers of abstraction. Currently, four layers are supported:
```python
class CyberAbstractionLevel(IntEnum):
    HIGH = 0
    ALGORITHMIC = 1
    SOURCE = 2
    BINARY = 3
```

As you go lower in the abstraction, more "variables" are available for constraining. 
When modelling a component, like a `Motor`, you must at a minimum describe its `High` abstraction.

## Usage
Use SACI as a Python library. Take a look at the example folder for all the code.
First, model the device:
```python
class PX4Quadcopter(Device):
    def __init__(self):
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
            ], create_using=nx.DiGraph)
        )
```

Many sub-components have functions which can be overridden for deeper analysis. As an example, 
`GCSTelemetryHigh` has a function called `accepts_communication`, which can be used to constrain how this component
receives external communications 

Next model the vulnerability used in the CPV:
```python
class MavlinkVuln01(Vulnerability):
    def __init__(self):
        super().__init__(
            component=TelemetryAlgorithmic,
            _input=AuthenticatedCommunication(),
            output=AuthenticatedCommunication(),
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # if it's the Mavlink protocol we don't need to do any symbolic check since
            # we are already aware that it's vulnerable to this attack
            if isinstance(comp, TelemetryHigh) and comp.protocol_name == "mavlink":
                return True

            # check to see if we can achieve the following scenario:
            # 1. User A sends a packet, identifier is X
            # 2. User B sends a packer, identifier is also X
            # i.e., any case where two distinct users can get the same identifier is a vulnerability
            # (authentication failure)
            if isinstance(comp, TelemetryAlgorithmic):
                good_comm = AuthenticatedCommunication(src="192.168.1.2", dst="controller")
                bad_comm = AuthenticatedCommunication(src="192.168.1.3", dst="controller")
                if (good_comm.src != bad_comm.src) and (good_comm.identifier == bad_comm.identifier):
                    return True
```

Model the CPV:
```python
class MavlinkCPV(CPV):
    def __init__(self):
        mavlink_vuln = MavlinkVuln01()
        super().__init__(
            required_components=[
                mavlink_vuln.component,
                TelemetryHigh,
                ControllerHigh,
                MultiCopterMotorHigh,
                MultiCopterMotorAlgo,
            ],
            # TODO: how to describe what kind of input is needed
            entry_component=TelemetryHigh(powered=True),
            vulnerabilities=[mavlink_vuln]
        )

        # We want the motor to be powered, but to be doing nothing. This can be described as neither
        # having lift, pitch, or yaw.
        gms = MultiCopterMotorAlgo()
        gms.conditions = [
            gms.v["yaw"] == 0,
            gms.v["pitch"] == 0,
            gms.v["lift"] == 0,
        ]
        self.goal_motor_state = gms

    def in_goal_state(self, state: GlobalState):
        for component in state.components:
            if isinstance(component, MultiCopterMotorHigh):
                if not component.powered:
                    return False
            elif isinstance(component, MultiCopterMotorAlgo):
                if component != self.goal_motor_state:
                    return False
            elif isinstance(component, TelemetryHigh) and not component.powered:
                return False
            elif isinstance(component, ControllerHigh) and not component.powered:
                return False
```

Finally, use the `Identifier` to check if the CPV(s) exist in the device:

```python
from saci.identifier.identifier import Identifier
from saci.modeling.state.global_state import GlobalState
from cpv01_mitm_mavlink.cpv import MavlinkCPV
from px4_quadcopter_device import PX4Quadcopter, GCSTelemetryHigh, PX4ControllerHigh, MultiCopterMotorHigh

cpv = MavlinkCPV()
device = PX4Quadcopter(
    state=GlobalState([
        GCSTelemetryHigh(powered=True), GCSTelemetryHigh(powered=True), MultiCopterMotorHigh(powred=True)
    ])
)
identifier = Identifier(device, [cpv])
paths = identifier.identify()
```


### Run with examples

1. `saci -r orchestrator -y tests/hypothesis_wifi.json`, this is to take a user hypothesis as input and check if such a CPV exist in the device, by checking if the corresponding components and vulnerabilities exist.

### Run the web server

1. `saci -r web`

### Run the web server with Docker

1. `docker build -t saci .`
2. `docker run -p 8000:8000 saci`
