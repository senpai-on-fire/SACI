from saci.modeling import CPV
from saci.modeling.device import TelemetryHigh, ControllerHigh, MultiCopterMotorHigh, MultiCopterMotorAlgo
from saci.modeling.state import GlobalState

from .vuln import MavlinkVuln01


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
