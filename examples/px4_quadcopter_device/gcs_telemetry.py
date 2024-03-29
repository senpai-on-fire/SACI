from saci.modeling.communication import AuthenticatedCommunication
from saci.modeling.device import TelemetryHigh, TelemetryAlgorithmic


class GCSTelemetryHigh(TelemetryHigh):
    def __init__(self):
        super().__init__(name="gcs_telemetry_high", protocol_name="mavlink")


class GCSTelemetryAlgo(TelemetryAlgorithmic):
    def __init__(self, system_id):
        super().__init__(name="gcs_telemetry_algo")
        self.system_id = system_id

    def accepts_communication(self, communication: AuthenticatedCommunication) -> bool:
        if communication.identifier == self.system_id:
            return True
