from ..component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberAbstractionLevel
from claripy import BVS

class DCMotorHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class DCMotorAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        #
        # Symbolic Variables for DC Motor
        #
        # These are some of the key variables that might be relevant
        # in analyzing or simulating DC motor behavior.
        #
        # Voltage applied to the dc_motor
        self.variables["voltage"] = BVS("dc_motor_voltage", 64)
        # Current flowing through the dc_motor
        self.variables["current"] = BVS("dc_motor_current", 64)
        # The dc_motor’s torque output
        self.variables["torque"] = BVS("dc_motor_torque", 64)
        # The angular velocity (or speed) of the dc_motor
        self.variables["speed"] = BVS("dc_motor_speed", 64)
        # If more precise tracking of the dc_motor shaft position is needed
        self.variables["position"] = BVS("dc_motor_position", 64)
        # Temperature, if thermal effects are part of your analysis
        self.variables["temperature"] = BVS("dc_motor_temperature", 64)
        # Mechanical or electrical power consumed/produced by the dc_motor
        self.variables["power"] = BVS("dc_motor_power", 64)
        # Efficiency in converting electrical power to mechanical power
        self.variables["efficiency"] = BVS("dc_motor_efficiency", 64)


class DCMotor(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: DCMotorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: DCMotorAlgorithmic(),
        }
