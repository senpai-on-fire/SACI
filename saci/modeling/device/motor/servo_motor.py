from ..component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberAbstractionLevel
from claripy import BVS

class ServoHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Define any high-level attributes or methods for the servo here if needed.

class ServoAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        #
        # Symbolic Variables for Servo Motor
        #
        # Below are some example variables often relevant in servo motor modeling and simulation
        #
        # Voltage applied to the servo
        self.variables["voltage"] = BVS("servo_voltage", 64)
        # Current flowing through the servo
        self.variables["current"] = BVS("servo_current", 64)
        # The servo’s torque output
        self.variables["torque"] = BVS("servo_torque", 64)
        # The shaft angle of the servo (or general position)
        self.variables["angle"] = BVS("servo_angle", 64)
        # The angular velocity (or speed) of the servo
        self.variables["speed"] = BVS("servo_speed", 64)
        # If more precise tracking of the servo shaft position is needed
        self.variables["position"] = BVS("servo_position", 64)
        # Temperature, if thermal effects are part of your analysis
        self.variables["temperature"] = BVS("servo_temperature", 64)
        # Mechanical or electrical power consumed/produced by the servo
        self.variables["power"] = BVS("servo_power", 64)
        # Efficiency in converting electrical power to mechanical power
        self.variables["efficiency"] = BVS("servo_efficiency", 64)

class Servo(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ServoHigh(),
            CyberAbstractionLevel.ALGORITHMIC: ServoAlgorithmic(),
        }
