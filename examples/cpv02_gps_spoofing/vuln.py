from saci.modeling import Vulnerability
from saci.modeling.device import GPSReceiver, GPSReceiverAlgorithm, Device
from saci.modeling.communication import UnauthenticatedCommunication

class GPSSpoofingVuln01(Vulnerability):
    def __init__(self):
        super().__init__(
            component=GPSReceiver,
            # Input here would be the unauthenticated, spoofed GPS signals
            _input=UnauthenticatedCommunication(),
            # Output would be erroneous navigation decisions based on spoofed signals
            output=UnauthenticatedCommunication(),
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the device uses GPS for navigation and if the GPS signals are not authenticated
            if isinstance(comp, GPSReceiver) and comp.is_spoofable:
                return True

        return False
