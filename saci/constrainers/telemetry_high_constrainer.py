
from .base_constrainer import BaseConstrainer
from ..modeling.device import TelemetryHigh
from ..modeling.behavior import Behaviors, StringBehavior
from ..modeling.communication import UnauthenticatedCommunication, AuthenticatedCommunication


class TelemetryHighConstrainer(BaseConstrainer):
    @classmethod
    def supports(cls, component: TelemetryHigh) -> bool:
        return isinstance(component, TelemetryHigh)

    def solve(self, component: TelemetryHigh, output, out_state, behaviors, constraints):
        if output:
            behaviors = None
            if component.communication is None or isinstance(component.communication, UnauthenticatedCommunication):
                # just send data
                behaviors = None
            elif isinstance(component.communication, AuthenticatedCommunication):
                # must sniff
                comm_identifier = component.communication.identifier
                behaviors = Behaviors([StringBehavior(f"Sniff {comm_identifier}")])

            return True, {
                "input": output,
                "input_state": out_state,
                "behaviors": behaviors,
                "constraints": None,
            }
        
        return True, {
            "input": None,
            "input_state": None,
            "behaviors": None,
            "constraints": None,
        }
