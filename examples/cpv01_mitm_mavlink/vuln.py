from saci.modeling import Vulnerability
from saci.modeling.device import TelemetryHigh, TelemetryAlgorithmic, Device
from saci.modeling.communication import AuthenticatedCommunication


class MavlinkVuln01(Vulnerability):
    def __init__(self):
        super().__init__(
            component=TelemetryAlgorithmic,
            # TODO: how to express input/output constraints
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
                # TODO: how to express these properties could be symbolic? We essentially need a way to check
                #   that a telemetry can send an arbitrary constructed packet. For now, we just put a fake
                #   two packets there (always true for now)
                good_comm = AuthenticatedCommunication(src="192.168.1.2", dst="controller")
                bad_comm = AuthenticatedCommunication(src="192.168.1.3", dst="controller")
                if (good_comm.src != bad_comm.src) and (good_comm.identifier == bad_comm.identifier):
                    return True

