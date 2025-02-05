from .component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel

class GCS(CyberComponentBase):

    __slots__ = ("ABSTRACTIONS", "communication_protocols")

    def __init__(self, communication_protocols=None, **kwargs):
        """
        :param communication_protocols: Supported communication protocols for UAV interaction.
        """
        super().__init__(**kwargs)

        self.communication_protocols = communication_protocols or []

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: GCSHigh(communication_protocols=self.communication_protocols),
            CyberAbstractionLevel.ALGORITHMIC: GCSAlgorithmic(communication_protocols=self.communication_protocols),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


class GCSHigh(CyberComponentHigh):

    __slots__ = ("communication_protocols", "connected_uavs", "mission_status")

    def __init__(self, communication_protocols=None, connected_uavs=None, mission_status="IDLE", **kwargs):
        """
        :param communication_protocols: List of communication protocols the GCS supports (e.g., MAVLink, custom protocols).
        :param connected_uavs: List of currently connected UAVs.
        :param mission_status: Current mission status (e.g., "IDLE", "IN_PROGRESS", "COMPLETED").
        """
        super().__init__(**kwargs)
        self.communication_protocols = communication_protocols or []
        self.connected_uavs = connected_uavs or []
        self.mission_status = mission_status


class GCSAlgorithmic(CyberComponentAlgorithmic):

    __slots__ = ("communication_protocols", "connected_uavs", "mission_status", "telemetry_buffer")

    def __init__(self, communication_protocols=None, connected_uavs=None, mission_status="IDLE", telemetry_buffer=None, **kwargs):
        """
        :param communication_protocols: List of communication protocols the GCS supports.
        :param connected_uavs: List of currently connected UAVs.
        :param mission_status: Current mission status (e.g., "IDLE", "IN_PROGRESS", "COMPLETED").
        :param telemetry_buffer: Stores telemetry data received from UAVs.
        """
        super().__init__(**kwargs)
        self.communication_protocols = communication_protocols or []
        self.connected_uavs = connected_uavs or []
        self.mission_status = mission_status
        self.telemetry_buffer = telemetry_buffer or []

    def receives_telemetry(self, telemetry_data):
        """
        Handles incoming telemetry data from UAVs.
        :param telemetry_data: The telemetry packet received from a UAV.
        """
        self.telemetry_buffer.append(telemetry_data)

    def send_command(self, uav_id, command):
        """
        Sends a command to a specific UAV.
        :param uav_id: The unique identifier of the UAV.
        :param command: The command to be executed (e.g., "LAND", "RETURN_HOME").
        """
        if uav_id in self.connected_uavs:
            print(f"Sending command '{command}' to UAV {uav_id}")
            return True
        else:
            print(f"Failed to send command. UAV {uav_id} not connected.")
            return False

    def update_mission_status(self, status):
        """
        Updates the mission status of the GCS.
        :param status: The new mission status.
        """
        self.mission_status = status
        print(f"Mission status updated to {self.mission_status}")
