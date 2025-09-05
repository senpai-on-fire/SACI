from saci.modeling.device.component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
)
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class ObstacleAvoidanceLogicHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("avoidance_strategy", "detection_range")

    def __init__(self, avoidance_strategy=None, detection_range=5.0, **kwargs):
        """
        :param avoidance_strategy: High-level description of the avoidance strategy (e.g., Reactive, Predictive).
        :param detection_range: The distance within which obstacles are detected.
        """
        super().__init__(**kwargs)
        self.avoidance_strategy = avoidance_strategy
        self.detection_range = detection_range


class ObstacleAvoidanceLogicAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + ("avoidance_strategy", "detection_range", "algorithm_parameters")

    def __init__(self, avoidance_strategy=None, detection_range=5.0, algorithm_parameters=None, **kwargs):
        """
        :param avoidance_strategy: Detailed description of the avoidance strategy (e.g., potential fields, velocity
        obstacles).
        :param detection_range: The distance within which obstacles are detected.
        :param algorithm_parameters: Parameters for fine-tuning the avoidance algorithm.
        """
        super().__init__(**kwargs)
        self.avoidance_strategy = avoidance_strategy
        self.detection_range = detection_range
        self.algorithm_parameters = algorithm_parameters or {
            "reaction_time": 0.5,  # Time to react to obstacles
            "safe_distance": 1.5,  # Minimum distance to maintain from obstacles
            "sensor_accuracy": 0.9,  # Assumed accuracy of obstacle detection sensors
        }


class ObstacleAvoidanceLogic(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "avoidance_strategy", "detection_range", "algorithm_parameters")

    def __init__(self, avoidance_strategy=None, detection_range=5.0, algorithm_parameters=None, **kwargs):
        """
        :param avoidance_strategy: Strategy used for obstacle avoidance (e.g., Reactive, Predictive).
        :param detection_range: The detection range for obstacles.
        :param algorithm_parameters: Fine-tuning parameters for the avoidance algorithm.
        """
        super().__init__(**kwargs)

        self.avoidance_strategy = avoidance_strategy
        self.detection_range = detection_range
        self.algorithm_parameters = algorithm_parameters or {
            "reaction_time": 0.5,
            "safe_distance": 1.5,
            "sensor_accuracy": 0.9,
        }

        # Define abstractions for different cyber abstraction levels
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ObstacleAvoidanceLogicHigh(
                avoidance_strategy=avoidance_strategy,
                detection_range=detection_range,
            ),
            CyberAbstractionLevel.ALGORITHMIC: ObstacleAvoidanceLogicAlgorithmic(
                avoidance_strategy=avoidance_strategy,
                detection_range=detection_range,
                algorithm_parameters=self.algorithm_parameters,
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
