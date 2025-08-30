from saci.modeling.device.component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class SpeedControlLogicHigh(CyberComponentHigh):
    __slots__ = ("max_speed", "min_speed", "current_speed")

    def __init__(self, max_speed=20.0, min_speed=0.0, current_speed=0.0, **kwargs):
        """
        :param max_speed: Maximum allowed UAV speed.
        :param min_speed: Minimum allowed UAV speed.
        :param current_speed: Current speed of the UAV.
        """
        super().__init__(**kwargs)
        self.max_speed = max_speed
        self.min_speed = min_speed
        self.current_speed = current_speed


class SpeedControlLogicAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = ("max_speed", "min_speed", "current_speed", "speed_adjustment_params")

    def __init__(self, max_speed=20.0, min_speed=0.0, current_speed=0.0, speed_adjustment_params=None, **kwargs):
        """
        :param max_speed: Maximum allowed UAV speed.
        :param min_speed: Minimum allowed UAV speed.
        :param current_speed: Current speed of the UAV.
        :param speed_adjustment_params: Parameters for dynamic speed control.
        """
        super().__init__(**kwargs)
        self.max_speed = max_speed
        self.min_speed = min_speed
        self.current_speed = current_speed
        self.speed_adjustment_params = speed_adjustment_params or {
            "acceleration_rate": 1.0,  # Rate at which the UAV accelerates (m/s²)
            "deceleration_rate": 1.5,  # Rate at which the UAV decelerates (m/s²)
            "wind_resistance_factor": 0.1,  # Wind resistance effect on speed
        }

    def adjust_speed(self, target_speed):
        """
        Adjusts speed dynamically while respecting constraints.
        :param target_speed: Desired speed to achieve.
        :return: Updated UAV speed.
        """
        if target_speed > self.max_speed:
            target_speed = self.max_speed
        elif target_speed < self.min_speed:
            target_speed = self.min_speed

        if target_speed > self.current_speed:
            speed_change = min(
                self.speed_adjustment_params["acceleration_rate"],
                target_speed - self.current_speed,
            )
            self.current_speed += speed_change
        elif target_speed < self.current_speed:
            speed_change = min(
                self.speed_adjustment_params["deceleration_rate"],
                self.current_speed - target_speed,
            )
            self.current_speed -= speed_change

        # Apply wind resistance effect
        self.current_speed -= self.current_speed * self.speed_adjustment_params["wind_resistance_factor"]
        return self.current_speed


class SpeedControlLogic(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "max_speed", "min_speed", "current_speed", "speed_adjustment_params")

    def __init__(self, max_speed=20.0, min_speed=0.0, current_speed=0.0, speed_adjustment_params=None, **kwargs):
        """
        :param max_speed: Maximum speed limit.
        :param min_speed: Minimum speed limit.
        :param current_speed: Current UAV speed.
        :param speed_adjustment_params: Speed adjustment parameters for dynamic control.
        """
        super().__init__(**kwargs)

        self.max_speed = max_speed
        self.min_speed = min_speed
        self.current_speed = current_speed
        self.speed_adjustment_params = speed_adjustment_params or {
            "acceleration_rate": 1.0,
            "deceleration_rate": 1.5,
            "wind_resistance_factor": 0.1,
        }

        # Define abstractions for different cyber abstraction levels
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: SpeedControlLogicHigh(
                max_speed=self.max_speed,
                min_speed=self.min_speed,
                current_speed=self.current_speed,
            ),
            CyberAbstractionLevel.ALGORITHMIC: SpeedControlLogicAlgorithmic(
                max_speed=self.max_speed,
                min_speed=self.min_speed,
                current_speed=self.current_speed,
                speed_adjustment_params=self.speed_adjustment_params,
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
