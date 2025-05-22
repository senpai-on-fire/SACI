from saci.modeling.device.component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class EmergencyStopLogicHigh(CyberComponentHigh):
    __slots__ = ("trigger_source", "status")

    def __init__(self, trigger_source=None, status="IDLE", **kwargs):
        """
        :param trigger_source: The high-level source of emergency stop activation (e.g., manual, automated).
        :param status: The current status of the emergency stop system ("IDLE", "TRIGGERED", "RECOVERED").
        """
        super().__init__(**kwargs)
        self.trigger_source = trigger_source
        self.status = status


class EmergencyStopLogicAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = ("trigger_source", "status", "failsafe_conditions")

    def __init__(self, trigger_source=None, status="IDLE", failsafe_conditions=None, **kwargs):
        """
        :param trigger_source: Source of emergency stop activation.
        :param status: The status of the emergency stop system.
        :param failsafe_conditions: Conditions that trigger the emergency stop.
        """
        super().__init__(**kwargs)
        self.trigger_source = trigger_source
        self.status = status
        self.failsafe_conditions = failsafe_conditions or {
            "battery_low": 15.0,  # Battery below 15% triggers emergency stop
            "loss_of_signal": True,  # Loss of signal from GCS triggers emergency stop
            "hardware_fault": True,  # Detects critical failures (e.g., motor failure)
        }

    def check_conditions(self, telemetry_data):
        """
        Evaluates telemetry data against failsafe conditions to determine if an emergency stop is required.
        :param telemetry_data: Dictionary containing UAV telemetry data.
        :return: True if emergency stop is triggered, False otherwise.
        """
        if telemetry_data["battery"] < self.failsafe_conditions["battery_low"]:
            print("Emergency Stop Triggered: Low Battery!")
            self.status = "TRIGGERED"
            return True
        if telemetry_data["signal_lost"] and self.failsafe_conditions["loss_of_signal"]:
            print("Emergency Stop Triggered: Loss of Communication!")
            self.status = "TRIGGERED"
            return True
        if telemetry_data["hardware_fault"] and self.failsafe_conditions["hardware_fault"]:
            print("Emergency Stop Triggered: Hardware Fault Detected!")
            self.status = "TRIGGERED"
            return True
        return False

    def recover(self):
        """
        Implements recovery mechanism after an emergency stop.
        """
        if self.status == "TRIGGERED":
            print("Attempting Recovery...")
            self.status = "RECOVERED"
            return True
        return False


class EmergencyStopLogic(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "trigger_source", "status", "failsafe_conditions")

    def __init__(self, trigger_source=None, status="IDLE", failsafe_conditions=None, **kwargs):
        """
        :param trigger_source: Source that can trigger emergency stops.
        :param status: Current status of the emergency stop logic.
        :param failsafe_conditions: Set of conditions that trigger emergency stop.
        """
        super().__init__(**kwargs)

        self.trigger_source = trigger_source
        self.status = status
        self.failsafe_conditions = failsafe_conditions or {
            "battery_low": 15.0,
            "loss_of_signal": True,
            "hardware_fault": True,
        }

        # Define abstractions for different cyber abstraction levels
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: EmergencyStopLogicHigh(
                trigger_source=self.trigger_source,
                status=self.status,
            ),
            CyberAbstractionLevel.ALGORITHMIC: EmergencyStopLogicAlgorithmic(
                trigger_source=self.trigger_source,
                status=self.status,
                failsafe_conditions=self.failsafe_conditions,
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
