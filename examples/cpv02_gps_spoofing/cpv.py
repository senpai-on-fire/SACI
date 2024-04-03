from saci.modeling import CPV
from saci.modeling.device import (GPSReceiver, ControllerHigh, 
                                  CameraHigh, LocalizerHigh, LocalizerAlgorithm,
                                  MultiCopterMotorHigh, MultiCopterMotorAlgo)
from saci.modeling.state import GlobalState

from .vuln import GPSSpoofingVuln01


class GPSCPV(CPV):
    def __init__(self):
        gps_vuln = GPSSpoofingVuln01()
        super().__init__(
            required_components=[
                gps_vuln.component,
                CameraHigh,
                LocalizerHigh,
                LocalizerAlgorithm,
                ControllerHigh,
                MultiCopterMotorHigh,
                MultiCopterMotorAlgo,
            ],
            entry_component=GPSReceiver(powered=True),
            vulnerabilities=[gps_vuln]
        )

        # The goal_motor_state is redefined to represent the attacker's target localization state,
        # which involves incorrect localization due to GPS spoofing.
        # This condition needs to reflect the goal state that the attacker is targeting, 
        # possibly leading the drone to an unintended location.
        self.goal_state = LocalizerAlgorithm()
        # TODO: How to describe the target location?
        self.goal_state.conditions = [0.0, 0.0, 10.0]

    def in_goal_state(self, state: GlobalState):
        for component in state.components:
            if isinstance(component, LocalizerAlgorithm) and component.position() == self.goal_state.conditions:
                return True
