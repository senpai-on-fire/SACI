from pathlib import Path
import claripy

from saci.modeling.device.component import (
    ComponentBase,
    CyberComponentHigh,
    CyberAbstractionLevel,
    HardwareAbstractionLevel,
    HardwareHigh,
    CyberComponentBinary,
)
from ...state.operation_mode import OperationMode
from saci.modeling.device.component.cyber.cyber_component_binary import CyberComponentBinary


# =================== High-Level Abstraction (Cyber) ===================

class ControllerCyberHigh(CyberComponentHigh):

    __state_slots__ = CyberComponentHigh.__state_slots__ + (
        "in_failsafe_mode",
        "operating_mode",
        "navigation_mode",
        "autonomy_level",
        "variables",
    )
    __slots__ = CyberComponentHigh.__slots__ + (
        "in_failsafe_mode",
        "operating_mode",
        "navigation_mode",
        "autonomy_level",
        "variables",
    )

    def __init__(self, in_failsafe_mode=False, operating_mode=OperationMode.AUTONOMOUS, 
                 navigation_mode="GPS", autonomy_level=3, **kwargs):
        """
        :param operating_mode: Initial mode of operation (Default: AUTONOMOUS).
        :param in_failsafe_mode: Whether the autopilot is in failsafe mode.
        :param navigation_mode: Current navigation mode (e.g., "GPS", "Vision-based", "IMU").
        :param autonomy_level: Level of autonomy (1-5, where 5 is full autonomy).
        """
        super().__init__(**kwargs)

        self.operating_mode = operating_mode
        self.in_failsafe_mode = in_failsafe_mode
        self.navigation_mode = navigation_mode
        self.autonomy_level = autonomy_level

        # Symbolic variables for cyber operations and decision-making
        self.variables = {
            "autopilot_command": claripy.BVS("autopilot_command", 32),
            "autopilot_safety_check": claripy.BVS("autopilot_safety", 8),
            "autopilot_mode": claripy.BVS("autopilot_mode", 8),
        }

    @property
    def parameter_types(self):
        return {
            "in_failsafe_mode": bool,
            "operating_mode": OperationMode,
            "navigation_mode": str,
            "autonomy_level": int,
        }


# =================== High-Level Abstraction (Hardware) ===================

class ControllerHardwareHigh(HardwareHigh):

    __state_slots__ = HardwareHigh.__state_slots__ + (
        "has_pwm_transmitter",
        "has_redundant_sensors",
        "communication_protocol"
    )
    __slots__ = HardwareHigh.__slots__ + (
        "has_pwm_transmitter",
        "has_redundant_sensors",
        "communication_protocol"
    )

    def __init__(self, has_pwm_transmitter=True, has_redundant_sensors=True, 
                 communication_protocol="CAN", **kwargs):
        """
        :param has_pwm_transmitter: Whether the autopilot includes a PWM transmitter.
        :param has_redundant_sensors: Whether the autopilot has redundant sensors for safety.
        :param communication_protocol: Communication protocol used (e.g., "CAN", "UART", "I2C").
        """
        super().__init__(**kwargs)
        self.has_pwm_transmitter = has_pwm_transmitter
        self.has_redundant_sensors = has_redundant_sensors
        self.communication_protocol = communication_protocol

    @property
    def parameter_types(self):
        return {
            "has_pwm_transmitter": bool,
            "has_redundant_sensors": bool,
            "communication_protocol": str,
        }


# =================== Binary Abstraction (Firmware) ===================

class ControllerBinary(CyberComponentBinary):

    __state_slots__ = CyberComponentBinary.__state_slots__ + ("patch_status", "firmware_version")
    __slots__ = CyberComponentBinary.__slots__ + ("patch_status", "firmware_version")

    def __init__(self, binary_path: Path = None, pc: int = None, patch_status="up-to-date", 
                 firmware_version="v1.0", **kwargs):
        """
        :param binary_path: Path to the autopilot firmware binary.
        :param pc: Current program counter (for execution tracking).
        :param patch_status: Status of firmware security patches ("up-to-date", "outdated", "misconfigured").
        :param firmware_version: Current firmware version.
        """
        super().__init__(binary_path=binary_path, pc=pc, **kwargs)
        self.patch_status = patch_status
        self.firmware_version = firmware_version

    @property
    def parameter_types(self):
        return {
            "binary_path": Path,
            "patch_status": str,
            "firmware_version": str,
        }


# =================== Full Autopilot Controller Model ===================

class Controller(ComponentBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ControllerCyberHigh(),
            HardwareAbstractionLevel.HIGH: ControllerHardwareHigh(),
            CyberAbstractionLevel.BINARY: ControllerBinary(),
        }

    @property
    def parameter_types(self):
        return {
            "in_failsafe_mode": bool,
            "operating_mode": OperationMode,
            "navigation_mode": str,
            "autonomy_level": int,
            "has_pwm_transmitter": bool,
            "has_redundant_sensors": bool,
            "communication_protocol": str,
            "binary_path": Path,
            "patch_status": str,
            "firmware_version": str,
        }


######################################################    OLD VERSION    ########################################################################


# from pathlib import Path
# from .component import (
#     ComponentBase,
#     CyberComponentHigh,
#     CyberAbstractionLevel,
#     HardwareAbstractionLevel,
#     HardwareHigh,
#     CyberComponentHigh,
# )
# from ..state.operation_mode import OperationMode
# from saci.modeling.device.component.cyber.cyber_component_binary import CyberComponentBinary


# class ControllerCyberHigh(CyberComponentHigh):
#     __state_slots__ = CyberComponentHigh.__state_slots__ + ("in_failsafe_mode", "operating_mode")
#     __slots__ = CyberComponentHigh.__slots__ + ("in_failsafe_mode", "operating_mode")

#     def __init__(self, in_failsafe_mode=False, operating_mode=OperationMode.MANUAL, **kwargs):
#         """
#         :param operating_mode, initialized to MANUAL mode
#         :param in_failsafe_mode:
#         :param kwargs:
#         """
#         super().__init__(**kwargs)
#         self.operating_mode = operating_mode
#         self.in_failsafe_mode = in_failsafe_mode

#     @property
#     def parameter_types(self):
#         return {
#             "has_integrity_check": bool,
#         }


# class ControllerHardwareHigh(HardwareHigh):
#     __state_slots__ = HardwareHigh.__state_slots__ + ("has_pwm_transmitter",)
#     __slots__ = HardwareHigh.__slots__ + ("has_pwm_transmitter",)

#     def __init__(self, has_pwm_transmitter=True, **kwargs):
#         """
#         :param has_pwm_transmitter:
#         :param kwargs:
#         """
#         super().__init__(**kwargs)
#         self.has_pwm_transmitter = has_pwm_transmitter

#     @property
#     def parameter_types(self):
#         return {
#             "has_pwm_transmitter": bool,
#         }


# class ControllerBinary(CyberComponentBinary):
#     __state_slots__ = CyberComponentBinary.__state_slots__ + ("patch_status",)
#     __slots__ = CyberComponentBinary.__slots__ + ("patch_status",)

#     def __init__(self, binary_path: Path = None, pc: int = None, patch_status="up-to-date", **kwargs):
#         """
#         :param binary_path: Path to the binary firmware file.
#         :param pc: Current program counter (for simulation purposes).
#         :param patch_status: The status of the firmware patch ('up-to-date', 'outdated', or 'misconfigured').
#         :param kwargs: Additional parameters.
#         """
#         super().__init__(binary_path=binary_path, pc=pc, **kwargs)
#         self.patch_status = patch_status

#     @property
#     def parameter_types(self):
#         return {
#             "binary_path": Path,
#             "patch_status": str,
#         }


# class Controller(ComponentBase):
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.ABSTRACTIONS = {
#             CyberAbstractionLevel.HIGH: ControllerCyberHigh(),
#             HardwareAbstractionLevel.HIGH: ControllerHardwareHigh(),
#             CyberAbstractionLevel.BINARY: ControllerBinary(),
#         }

#     @property
#     def parameter_types(self):
#         return {
#             "has_integrity_check": bool,
#             "in_failsafe_mode": bool,
#             "has_pwm_transmitter": bool,
#             "binary_path": Path,
#             "patch_status": str,
#         }
