import logging

import claripy

from saci.modeling.device.component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
)
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class ObjectAvoidanceDNNHigh(CyberComponentHigh):
    """
    High-level abstraction for an object avoidance DNN.
    This level provides a general overview of the model's avoidance behavior and security properties.
    """

    __slots__ = CyberComponentHigh.__slots__ + (
        "known_source",
        "known_weight",
        "is_trusted",
        "avoidance_accuracy",
        "false_negative_rate",
        "variables",
    )

    def __init__(
        self,
        known_source=None,
        known_weight=None,
        is_trusted=True,
        avoidance_accuracy=0.98,
        false_negative_rate=0.03,
        **kwargs,
    ):
        """
        :param known_source: Verified source of the DNN model.
        :param known_weight: Verified weights used in the DNN.
        :param is_trusted: Boolean flag indicating if the DNN model is trusted.
        :param avoidance_accuracy: Percentage of successful obstacle avoidance (0 to 1).
        :param false_negative_rate: Percentage of missed obstacle detections (0 to 1).
        """
        super().__init__(**kwargs)
        self.known_source = known_source
        self.known_weight = known_weight
        self.is_trusted = is_trusted
        self.avoidance_accuracy = avoidance_accuracy
        self.false_negative_rate = false_negative_rate  # Critical for safety in UAV navigation.

        # Symbolic variables for AI security testing
        self.variables = {
            "dnn_model_integrity": claripy.BVS("dnn_model_integrity", 8),  # Model integrity status
            "dnn_adversarial_attack_flag": claripy.BVS(
                "dnn_adversarial_attack_flag", 8
            ),  # Adversarial attack detection
            "dnn_bias_flag": claripy.BVS("dnn_bias_flag", 8),  # Bias detection in the model
        }

    parameter_types = {
        "known_source": str,
        "known_weight": str,
        "is_trusted": bool,
        "avoidance_accuracy": float,
        "false_negative_rate": float,
    }


# =================== Algorithmic Abstraction (Cyber) ===================


class ObjectAvoidanceDNNAlgorithmic(CyberComponentAlgorithmic):
    """
    Algorithmic-level abstraction for an object avoidance DNN.
    Implements real-time avoidance logic, model security properties, and robustness testing.
    """

    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "known_source",
        "known_weight",
        "adversarial_defense",
        "avoidance_latency",
        "reaction_time",
        "safe_distance_threshold",
        "adversarial_noise_sensitivity",
        "sensor_fusion_reliability",
        "backdoor_flag",
        "variables",
    )

    def __init__(
        self,
        known_source=None,
        known_weight=None,
        adversarial_defense=True,
        avoidance_latency=40,
        reaction_time=100,
        safe_distance_threshold=2.0,
        adversarial_noise_sensitivity=0.1,
        sensor_fusion_reliability=0.95,
        **kwargs,
    ):
        """
        :param known_source: Verified source of the DNN model.
        :param known_weight: Verified weights used in the DNN.
        :param adversarial_defense: Boolean indicating if the model has adversarial defense.
        :param avoidance_latency: Inference time per frame in milliseconds.
        :param reaction_time: Time delay between detection and UAV action in milliseconds.
        :param safe_distance_threshold: Minimum safe distance (meters) before avoidance is triggered.
        :param adversarial_noise_sensitivity: How easily the system is affected by noise (0 to 1).
        :param sensor_fusion_reliability: How well sensor fusion (LiDAR, radar, vision) performs (0 to 1).
        """
        super().__init__(**kwargs)
        self.known_source = known_source
        self.known_weight = known_weight
        self.adversarial_defense = adversarial_defense
        self.avoidance_latency = avoidance_latency
        self.reaction_time = reaction_time
        self.safe_distance_threshold = safe_distance_threshold
        self.adversarial_noise_sensitivity = adversarial_noise_sensitivity
        self.sensor_fusion_reliability = sensor_fusion_reliability

        # Security-related symbolic variables
        self.variables = {
            "dnn_confidence_score": claripy.BVS("dnn_confidence_score", 32),  # Model confidence in object avoidance
            "dnn_training_data_integrity": claripy.BVS("dnn_training_data_integrity", 8),  # Data integrity flag
            "dnn_inference_latency": claripy.BVS("dnn_inference_latency", 32),  # Latency in inference
            "dnn_adversarial_robustness": claripy.BVS(
                "dnn_adversarial_robustness", 8
            ),  # Robustness against adversarial attacks
            "backdoor_flag": claripy.BVS("dnn_backdoor_flag", 8),  # Flags possible backdoor insertion in the model
        }

    parameter_types = {
        "known_source": str,
        "known_weight": str,
        "adversarial_defense": bool,
        "avoidance_latency": int,
        "reaction_time": int,
        "safe_distance_threshold": float,
        "adversarial_noise_sensitivity": float,
        "sensor_fusion_reliability": float,
    }


# =================== Full Object Avoidance DNN Model (Cyber) ===================


class ObjectAvoidanceDNN(CyberComponentBase):
    """
    Core component for an object avoidance DNN system.
    Integrates different abstraction levels (High, Algorithmic, Source, and Binary).
    """

    __slots__ = (
        "ABSTRACTIONS",
        "known_source",
        "known_weight",
        "adversarial_defense",
        "avoidance_latency",
        "variables",
    )

    def __init__(self, known_source=None, known_weight=None, adversarial_defense=True, avoidance_latency=40, **kwargs):
        """
        :param known_source: Verified model source.
        :param known_weight: Verified model weights.
        :param adversarial_defense: Boolean indicating if the model has adversarial defense enabled.
        :param avoidance_latency: Inference time per frame in milliseconds.
        """
        super().__init__(**kwargs)

        self.known_source = known_source
        self.known_weight = known_weight
        self.adversarial_defense = adversarial_defense
        self.avoidance_latency = avoidance_latency

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ObjectAvoidanceDNNHigh(
                known_source=known_source, known_weight=known_weight, is_trusted=True
            ),
            CyberAbstractionLevel.ALGORITHMIC: ObjectAvoidanceDNNAlgorithmic(
                known_source=known_source,
                known_weight=known_weight,
                adversarial_defense=adversarial_defense,
                avoidance_latency=avoidance_latency,
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
